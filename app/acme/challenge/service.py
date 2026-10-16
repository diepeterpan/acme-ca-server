import asyncio
import base64
import hashlib
import ipaddress
import socket
from typing import Literal

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import jwcrypto.jwk
from config import settings
from fastapi import status

from ..exceptions import ACMEException


def compute_dns_key_authorization_digest(token: str, jwk: jwcrypto.jwk.JWK) -> str:
    key_authorization = f'{token}.{jwk.thumbprint()}'
    digest = hashlib.sha256(key_authorization.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


async def _resolve_nameserver(entry: str) -> tuple[str, int]:
    port = 53
    host = entry
    if ':' in entry:
        parts = entry.rsplit(':', 1)
        host = parts[0]
        port = int(parts[1])
    try:
        ipaddress.ip_address(host)
        return host, port
    except ValueError:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(host, port, family=socket.AF_INET)
        ip = str(addr_info[0][4][0])
        return ip, port


async def check_challenge_is_fulfilled(*, domain: str, token: str, jwk: jwcrypto.jwk.JWK, new_nonce: str | None = None):
    for _ in range(3):  # 3x retry
        err: Literal[False] | ACMEException
        try:
            async with httpx.AsyncClient(
                timeout=10,
                # only http 1.0/1.1 is required, not https
                verify=False,  # noqa: S501 (https is intentionally disabled)
                http1=True,
                http2=False,
                # todo: redirects are forbidden for now, but RFC states redirects should be supported
                follow_redirects=False,
                trust_env=False,  # do not load proxy information from env vars
            ) as client:
                res = await client.get(f'http://{domain}:80/.well-known/acme-challenge/{token}')
                if res.status_code == 200 and res.text.rstrip() == f'{token}.{jwk.thumbprint()}':
                    err = False
                else:
                    err = ACMEException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        exctype='incorrectResponse',
                        detail='presented token does not match challenge',
                        new_nonce=new_nonce,
                    )
        except httpx.ConnectTimeout:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='connection', detail='timeout', new_nonce=new_nonce)
        except httpx.ConnectError:
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='dns', detail='could not resolve address', new_nonce=new_nonce)
        except Exception:  # noqa: BLE001
            err = ACMEException(status_code=status.HTTP_400_BAD_REQUEST, exctype='serverInternal', detail='could not validate challenge', new_nonce=new_nonce)
        if err is False:
            return  # check successful
        await asyncio.sleep(3)
    raise err  # type: ignore[misc]


async def check_dns_challenge_is_fulfilled(*, domain: str, token: str, jwk: jwcrypto.jwk.JWK, new_nonce: str | None = None):
    expected_txt_value = compute_dns_key_authorization_digest(token, jwk)
    clean_domain = domain.removeprefix('*.')
    record_name = f'_acme-challenge.{clean_domain}'

    resolver = dns.asyncresolver.Resolver()
    if settings.acme.dns_resolvers:
        nameservers: list[str] = []
        port = 53
        entries = [settings.acme.dns_resolvers] if isinstance(settings.acme.dns_resolvers, str) else settings.acme.dns_resolvers
        for entry in entries:
            try:
                ip, p = await _resolve_nameserver(entry)
                nameservers.append(ip)
                port = p
            except Exception as e:
                raise ACMEException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    exctype='dns',
                    detail=f'could not resolve nameserver {entry}: {e}',
                    new_nonce=new_nonce,
                ) from e
        resolver.nameservers = nameservers
        resolver.port = port

    resolver.lifetime = settings.acme.dns_timeout

    for _ in range(settings.acme.dns_retries):
        err: Literal[False] | ACMEException
        try:
            answers = await resolver.resolve(record_name, 'TXT')
            found_values: list[str] = []
            for rdata in answers:
                txt_val = b''.join(rdata.strings).decode('utf-8', errors='replace').strip()
                found_values.append(txt_val)

            if expected_txt_value in found_values:
                err = False
            else:
                err = ACMEException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    exctype='incorrectResponse',
                    detail=f'presented TXT record for {record_name} does not match expected digest',
                    new_nonce=new_nonce,
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            err = ACMEException(
                status_code=status.HTTP_400_BAD_REQUEST,
                exctype='dns',
                detail=f'no TXT record found for {record_name}',
                new_nonce=new_nonce,
            )
        except (dns.exception.Timeout, TimeoutError):
            err = ACMEException(
                status_code=status.HTTP_400_BAD_REQUEST,
                exctype='connection',
                detail=f'DNS query timed out resolving {record_name}',
                new_nonce=new_nonce,
            )
        except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            err = ACMEException(
                status_code=status.HTTP_400_BAD_REQUEST,
                exctype='dns',
                detail=f'could not reach DNS nameservers for {record_name}',
                new_nonce=new_nonce,
            )
        except Exception as exc:  # noqa: BLE001
            err = ACMEException(
                status_code=status.HTTP_400_BAD_REQUEST,
                exctype='serverInternal',
                detail=f'could not validate DNS challenge: {exc}',
                new_nonce=new_nonce,
            )

        if err is False:
            return  # check successful
        await asyncio.sleep(2)
    raise err  # type: ignore[misc]
