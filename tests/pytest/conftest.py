import asyncio
import json
import os
import shutil
import subprocess
from collections.abc import Generator
from pathlib import Path

import httpx
import jwcrypto.jwk
import pytest
from fastapi.testclient import TestClient

# Configure test environment variables at module load time so all imported modules use test settings
ca_dir = Path(__file__).parent / 'import-ca'
os.environ['ca_encryption_key'] = 'M8L6RSYPiHHr6GogXmkQIs7gVia_K5fDDJiNK7zUt0k='
os.environ['external_url'] = 'http://localhost:8000/'
os.environ['acme_mail_required'] = 'False'
os.environ['web_admin_username'] = 'admin'
os.environ['web_admin_password'] = 'adminpassword123'
os.environ['ca_import_dir'] = str(ca_dir)
os.environ['db_integrity_enabled'] = 'False'

# Ensure test CA keys and certificates exist before any module imports Settings
shutil.rmtree(ca_dir, ignore_errors=True)
ca_dir.mkdir(parents=True, exist_ok=True)
subprocess.call(['openssl', 'genrsa', '-out', ca_dir / 'ca.key', '4096'])
subprocess.call(['openssl', 'req', '-new', '-x509', '-nodes', '-days', '3650', '-subj', '/C=DE/O=Demo', '-key', ca_dir / 'ca.key', '-out', ca_dir / 'ca.pem'])


@pytest.fixture(scope='session')
def testclient() -> Generator[TestClient, None, None]:
    async def noop():
        pass

    import config
    import main

    config.settings.ca.import_dir = ca_dir
    config.settings.db_integrity.enabled = False

    # cronjobs are disabled because they would keep the test run going even if all tests are done
    import acme
    import acme.certificate.cronjob
    import acme.nonce.cronjob
    import ca.cronjob

    ca.cronjob.start = noop
    acme.start_cronjobs = noop
    acme.certificate.cronjob.start = noop
    acme.nonce.cronjob.start = noop
    main.ca.cronjob.start = noop
    main.acme.start_cronjobs = noop

    main.app.state.maintenance_mode = False

    with TestClient(main.app) as tc:
        main.app.state.maintenance_mode = False
        # Authenticate web testclient with signed session cookie
        import web.auth

        token, _ = web.auth.create_session_cookie('admin', remember_me=True)
        tc.cookies[web.auth.COOKIE_NAME] = token
        yield tc


@pytest.fixture
def anon_client(testclient: TestClient) -> Generator[httpx.Client, None, None]:
    with httpx.Client(transport=testclient._transport, base_url='http://testserver') as client:
        yield client


@pytest.fixture(scope='session')
def directory(testclient: TestClient) -> dict[str, str]:
    return testclient.get('/acme/directory').json()


@pytest.fixture
def account_jwk() -> jwcrypto.jwk.JWK:
    jwk_key = jwcrypto.jwk.JWK.generate(kty='EC', crv='P-256')

    return jwk_key


@pytest.fixture
def signed_request(testclient: TestClient, account_jwk: jwcrypto.jwk.JWK, directory):
    class SignedRequest:
        @property
        def account_jwk(self):
            return account_jwk

        @property
        def nonce(self):
            return testclient.head(directory['newNonce']).headers['Replay-Nonce']

        def __call__(self, url: str, nonce: str, payload: dict | str, account_url: str | None = None):
            jws = jwcrypto.jws.JWS('' if payload == '' else json.dumps(payload))
            protected = {'alg': 'ES256', 'nonce': nonce, 'url': url}
            if account_url is None:
                protected['jwk'] = account_jwk.export_public(as_dict=True)
            else:
                protected['kid'] = account_url

            jws.add_signature(account_jwk, protected=protected)

            return testclient.post(url, content=jws.serialize(), headers={'Content-Type': 'application/jose+json'})

    return SignedRequest()


@pytest.fixture(scope='session')
def db():
    import asyncpg

    class DbConnector:
        @staticmethod
        def fetch_row(*args):
            import config

            async def do():
                connection = await asyncpg.connect(str(config.settings.db_dsn))
                stored_row = await connection.fetchrow(*args)
                await connection.close()
                return stored_row

            return asyncio.run(do())

    return DbConnector()


@pytest.fixture
def build_csr():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    def _build_csr(names: list[str]) -> x509.CertificateSigningRequest:
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, names[0])]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names[1:]]), critical=False)
            .sign(rsa.generate_private_key(65537, 2048), hashes.SHA256())
        )

    return _build_csr
