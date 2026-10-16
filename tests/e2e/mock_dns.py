#!/usr/bin/env python3
"""
Lightweight Mock DNS Server for ACME DNS-01 End-to-End Testing.
Provides:
  - UDP port 53: Responds to DNS TXT queries for _acme-challenge.*
  - TCP port 53: Responds to DNS queries over TCP
  - HTTP port 8053: REST API to dynamically add/remove/inspect DNS TXT records.
Zero external dependencies (pure Python standard library).
"""

import json
import logging
import socketserver
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(level=logging.INFO, format='[mock_dns] %(asctime)s - %(message)s')
logger = logging.getLogger('mock_dns')

# In-memory storage for DNS records: { "domain.lower()": ["txt_val1", ...] }
DNS_RECORDS: dict[str, list[str]] = {}
RECORDS_LOCK = threading.Lock()


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip('.')


def parse_dns_question(data: bytes) -> tuple[int, str, int, bytes] | None:
    if len(data) < 12:
        return None
    trans_id = struct.unpack('!H', data[:2])[0]
    idx = 12
    labels = []
    while idx < len(data):
        length = data[idx]
        if length == 0:
            idx += 1
            break
        idx += 1
        labels.append(data[idx:idx + length].decode('ascii', errors='ignore'))
        idx += length
    if idx + 4 > len(data):
        return None
    qname = '.'.join(labels)
    qtype, _ = struct.unpack('!HH', data[idx:idx + 4])
    question_bytes = data[12:idx + 4]
    return trans_id, normalize_domain(qname), qtype, question_bytes


def build_dns_response(data: bytes) -> bytes:
    parsed = parse_dns_question(data)
    if not parsed:
        return b''
    trans_id, qname, qtype, question_bytes = parsed

    with RECORDS_LOCK:
        txt_values = list(DNS_RECORDS.get(qname, []))

    logger.info('Query for %s (QTYPE=%d), matching records: %s', qname, qtype, txt_values)

    # QTYPE 16 is TXT, QTYPE 255 is ANY
    if qtype in (16, 255) and txt_values:
        flags = 0x8180  # Standard query response, No error
        ancount = len(txt_values)
        resp_header = struct.pack('!HHHHHH', trans_id, flags, 1, ancount, 0, 0)
        answers = bytearray()
        for val in txt_values:
            answers += struct.pack('!H', 0xc00c)  # Pointer to qname in question
            answers += struct.pack('!HHI', 16, 1, 60)  # Type TXT (16), Class IN (1), TTL 60
            v_bytes = val.encode('utf-8')
            answers += struct.pack('!HB', len(v_bytes) + 1, len(v_bytes)) + v_bytes
        return resp_header + question_bytes + bytes(answers)
    elif qtype in (16, 255) and not txt_values:
        flags = 0x8183  # NXDOMAIN
        resp_header = struct.pack('!HHHHHH', trans_id, flags, 1, 0, 0, 0)
        return resp_header + question_bytes
    else:
        # Default empty NOERROR for other types
        flags = 0x8180
        resp_header = struct.pack('!HHHHHH', trans_id, flags, 1, 0, 0, 0)
        return resp_header + question_bytes


class UDPDnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        sock = self.request[1]
        resp = build_dns_response(data)
        if resp:
            sock.sendto(resp, self.client_address)


class TCPDnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        len_bytes = self.request.recv(2)
        if len(len_bytes) < 2:
            return
        msg_len = struct.unpack('!H', len_bytes)[0]
        data = self.request.recv(msg_len)
        resp = build_dns_response(data)
        if resp:
            self.request.sendall(struct.pack('!H', len(resp)) + resp)


class HttpApiHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info('%s - %s', self.address_string(), format % args)

    def _send_json(self, status_code: int, data: dict):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        if self.path in ('/', '/records'):
            with RECORDS_LOCK:
                self._send_json(200, {'records': DNS_RECORDS})
        elif self.path == '/health':
            self._send_json(200, {'status': 'ok'})
        else:
            self._send_json(404, {'error': 'not found'})

    def do_POST(self):
        if self.path == '/records':
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len)
            try:
                payload = json.loads(body.decode('utf-8'))
                domain = normalize_domain(payload.get('domain', ''))
                value = payload.get('value', '').strip()
                if not domain or not value:
                    self._send_json(400, {'error': 'domain and value are required'})
                    return
                with RECORDS_LOCK:
                    if domain not in DNS_RECORDS:
                        DNS_RECORDS[domain] = []
                    if value not in DNS_RECORDS[domain]:
                        DNS_RECORDS[domain].append(value)
                logger.info('Added TXT record for %s: %s', domain, value)
                self._send_json(201, {'status': 'created', 'domain': domain, 'value': value})
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                self._send_json(400, {'error': str(e)})
            except Exception as e:  # noqa: BLE001
                self._send_json(500, {'error': str(e)})
        else:
            self._send_json(404, {'error': 'not found'})

    def do_DELETE(self):
        if self.path == '/records':
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len)
            try:
                payload = json.loads(body.decode('utf-8')) if body else {}
                domain = normalize_domain(payload.get('domain', '')) if payload else ''
                value = payload.get('value') if payload else None

                with RECORDS_LOCK:
                    if not domain:
                        DNS_RECORDS.clear()
                        logger.info('Cleared all DNS records')
                    elif domain in DNS_RECORDS:
                        if value:
                            DNS_RECORDS[domain] = [v for v in DNS_RECORDS[domain] if v != value]
                            if not DNS_RECORDS[domain]:
                                del DNS_RECORDS[domain]
                        else:
                            del DNS_RECORDS[domain]
                        logger.info('Removed records for %s', domain)
                self._send_json(200, {'status': 'deleted'})
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                self._send_json(400, {'error': str(e)})
            except Exception as e:  # noqa: BLE001
                self._send_json(500, {'error': str(e)})
        else:
            self._send_json(404, {'error': 'not found'})


def run_servers():
    dns_port = int(sys.argv[1]) if len(sys.argv) > 1 else 53
    http_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8053

    # UDP Server
    udp_server = socketserver.ThreadingUDPServer(('0.0.0.0', dns_port), UDPDnsHandler)
    udp_thread = threading.Thread(target=udp_server.serve_forever, daemon=True)
    udp_thread.start()
    logger.info('UDP DNS Server listening on 0.0.0.0:%d', dns_port)

    # TCP Server
    tcp_server = socketserver.ThreadingTCPServer(('0.0.0.0', dns_port), TCPDnsHandler)
    tcp_thread = threading.Thread(target=tcp_server.serve_forever, daemon=True)
    tcp_thread.start()
    logger.info('TCP DNS Server listening on 0.0.0.0:%d', dns_port)

    # HTTP API Server
    http_server = HTTPServer(('0.0.0.0', http_port), HttpApiHandler)
    logger.info('HTTP Mock DNS API listening on 0.0.0.0:%d', http_port)
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info('Shutting down servers...')
        udp_server.shutdown()
        tcp_server.shutdown()
        http_server.server_close()


if __name__ == '__main__':
    run_servers()
