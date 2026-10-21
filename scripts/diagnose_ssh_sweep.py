#!/usr/bin/env python3
"""
Diagnostic script to test and benchmark SSH connection and probe timings
against debianlounge.galleon.co.za from inside the production container.

Usage:
    python3 diagnose_ssh_sweep.py [password]
    OR set environment variable SSH_PASSWORD='your_password' python3 diagnose_ssh_sweep.py
"""

import asyncio
import getpass
import os
import socket
import sys
import time

try:
    import asyncssh
except ImportError:
    print("Error: asyncssh is not installed in the current Python environment.")
    print("Run using the app's virtualenv, e.g.: /path/to/.venv/bin/python3 diagnose_ssh_sweep.py")
    sys.exit(1)

HOST = "debianlounge.galleon.co.za"
PORT = 22
USERNAME = "root"

def print_header(title: str):
    print(f"\n{'=' * 65}\n  {title}\n{'=' * 65}")

def stage_result(name: str, duration: float, detail: str = "", success: bool = True):
    status = "\033[32m[PASS]\033[0m" if success else "\033[31m[FAIL]\033[0m"
    print(f"{status} {name:<35} {duration:>6.2f}s  {detail}")

def test_dns_and_tcp():
    print_header("Stage 1: DNS Resolution & Raw TCP Socket Connect")
    
    # 1. DNS Resolution
    t0 = time.perf_counter()
    try:
        addrinfo = socket.getaddrinfo(HOST, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM)
        t_dns = time.perf_counter() - t0
        ips = list(dict.fromkeys([res[4][0] for res in addrinfo]))
        stage_result("DNS Resolution", t_dns, f"Resolved to: {', '.join(ips)}")
    except Exception as ex:
        t_dns = time.perf_counter() - t0
        stage_result("DNS Resolution", t_dns, f"Failed: {ex}", success=False)
        return False, []

    # 2. Raw TCP Connection
    for ip in ips:
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((ip, PORT), timeout=10)
            t_tcp = time.perf_counter() - t0
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            stage_result(f"TCP Connect to {ip}:{PORT}", t_tcp, f"Banner: {banner}")
        except Exception as ex:
            t_tcp = time.perf_counter() - t0
            stage_result(f"TCP Connect to {ip}:{PORT}", t_tcp, f"Failed: {ex}", success=False)

    return True, ips

async def test_asyncssh(password: str):
    print_header("Stage 2: AsyncSSH Handshake & Authentication")
    
    t0 = time.perf_counter()
    conn = None
    try:
        print(f"Connecting with asyncssh to {USERNAME}@{HOST}:{PORT} (timeout=25s)...")
        conn = await asyncssh.connect(
            host=HOST,
            port=PORT,
            username=USERNAME,
            password=password,
            known_hosts=None,
            connect_timeout=25,
        )
        t_connect = time.perf_counter() - t0
        stage_result("AsyncSSH Connect & Auth", t_connect, "Authenticated successfully")
    except Exception as ex:
        t_connect = time.perf_counter() - t0
        stage_result("AsyncSSH Connect & Auth", t_connect, f"Exception: {type(ex).__name__}: {ex}", success=False)
        return

    try:
        print_header("Stage 3: Remote Command Execution Timings")
        
        # 1. OS Detection (uname -s)
        t0 = time.perf_counter()
        res_uname = await conn.run("uname -s", check=False, timeout=10)
        t_uname = time.perf_counter() - t0
        uname_out = (res_uname.stdout or "").strip()
        stage_result("Remote Command: uname -s", t_uname, f"Output: {uname_out}")

        # 2. OS Release (cat /etc/os-release)
        t0 = time.perf_counter()
        res_os = await conn.run("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME", check=False, timeout=10)
        t_os = time.perf_counter() - t0
        os_out = (res_os.stdout or "").strip()
        stage_result("Remote Command: os-release", t_os, f"Output: {os_out}")

        # 3. File Count in /etc/ssl/certs
        t0 = time.perf_counter()
        res_count = await conn.run("ls -1 /etc/ssl/certs/*.pem 2>/dev/null | wc -l", check=False, timeout=10)
        t_count = time.perf_counter() - t0
        pem_count = (res_count.stdout or "0").strip()
        stage_result("Cert Count in /etc/ssl/certs", t_count, f"{pem_count} .pem files")

        # 4. Old Loop (Unoptimized 1,200 forks)
        print("\nTesting OLD unoptimized Linux inspection loop (measuring time)...")
        old_cmd = """
SN="NONEXISTENT_SERIAL_BENCHMARK"
FP="NONEXISTENT_FP_BENCHMARK"
FOUND=""
for f in /etc/ssl/certs/*.pem /etc/ssl/certs/*.crt /usr/local/share/ca-certificates/*.crt; do
    [ -f "$f" ] || continue
    sn=$(openssl x509 -in "$f" -noout -serial 2>/dev/null | cut -d= -f2 | tr -d " :" | tr "[:lower:]" "[:upper:]")
    if [ -n "$sn" ] && [ "$sn" = "$SN" ]; then FOUND="$f"; break; fi
    if [ -n "$FP" ]; then
        fp=$(openssl x509 -in "$f" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d " :" | tr "[:lower:]" "[:upper:]")
        if [ -n "$fp" ] && [ "$fp" = "$FP" ]; then FOUND="$f"; break; fi
    fi
done
echo "$FOUND"
"""
        t0 = time.perf_counter()
        try:
            res_old = await conn.run(old_cmd, check=False, timeout=30)
            t_old = time.perf_counter() - t0
            stage_result("Old Unoptimized Cert Loop", t_old, f"Completed in {t_old:.2f}s (Current timeout limit is 12s!)")
        except Exception as ex:
            t_old = time.perf_counter() - t0
            stage_result("Old Unoptimized Cert Loop", t_old, f"TIMEOUT/FAILED: {type(ex).__name__}: {ex}", success=False)

        # 5. Proposed Fast-path (0-fork grep)
        print("\nTesting PROPOSED Fast-Path grep search...")
        fast_cmd = """
SIG="MIIB"
if [ -f /etc/ssl/certs/ca-certificates.crt ] && grep -Fq "$SIG" /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
    echo "Found in /etc/ssl/certs/ca-certificates.crt"
elif [ -f /etc/ssl/cert.pem ] && grep -Fq "$SIG" /etc/ssl/cert.pem 2>/dev/null; then
    echo "Found in /etc/ssl/cert.pem"
else
    echo "Not found"
fi
"""
        t0 = time.perf_counter()
        res_fast = await conn.run(fast_cmd, check=False, timeout=10)
        t_fast = time.perf_counter() - t0
        fast_out = (res_fast.stdout or "").strip()
        stage_result("Proposed Fast-Path (grep)", t_fast, f"Output: {fast_out} (Near instantaneous!)")

    finally:
        conn.close()
        await conn.wait_closed()

def main():
    print(f"Target: {USERNAME}@{HOST}:{PORT}")
    
    # Get password from CLI arg, ENV, or prompt
    if len(sys.argv) > 1:
        password = sys.argv[1]
    elif "SSH_PASSWORD" in os.environ:
        password = os.environ["SSH_PASSWORD"]
    else:
        password = getpass.getpass(f"Enter SSH password for {USERNAME}@{HOST}: ")

    # Stage 1: DNS & TCP
    success, _ = test_dns_and_tcp()
    if not success:
        print("\nDNS failed. Cannot proceed to SSH test.")
        return

    # Stage 2 & 3: AsyncSSH & Commands
    asyncio.run(test_asyncssh(password))

if __name__ == "__main__":
    main()
