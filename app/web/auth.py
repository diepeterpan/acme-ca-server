import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

import db
from config import settings
from logger import logger

COOKIE_NAME = 'acme_session'
_HAS_USERS_CACHE: bool = False


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with 600,000 iterations."""
    salt = secrets.token_bytes(16)
    iterations = 600000
    derived = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f'pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}'


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a stored hash string."""
    try:
        parts = password_hash.split('$')
        if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_hash = bytes.fromhex(parts[3])
        actual_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return hmac.compare_digest(actual_hash, expected_hash)
    except (ValueError, TypeError):
        return False


def get_signing_key() -> bytes:
    """Get HMAC secret key for signing session cookies."""
    if settings.web.session_secret:
        return settings.web.session_secret.get_secret_value().encode('utf-8')
    if settings.ca.encryption_key:
        return settings.ca.encryption_key.get_secret_value().encode('utf-8')
    return b'acme-ca-default-session-secret-key-at-least-32-bytes!'


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _b64url_decode(s: str) -> bytes:
    padding = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def create_session_cookie(username: str, remember_me: bool = False) -> tuple[str, int]:
    """Create a cryptographically signed session cookie value and return (cookie_str, max_age)."""
    max_age = 14 * 86400 if remember_me else 86400
    payload: dict[str, Any] = {
        'sub': username,
        'exp': int(time.time()) + max_age,
        'rnd': secrets.token_hex(8),
    }
    payload_raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    payload_b64 = _b64url_encode(payload_raw)

    sig = hmac.new(get_signing_key(), payload_b64.encode('ascii'), hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)

    token = f'{payload_b64}.{sig_b64}'
    return token, max_age


def verify_session_cookie(cookie_value: str | None) -> dict[str, Any] | None:
    """Verify a signed session cookie and return payload if valid."""
    if not cookie_value or '.' not in cookie_value:
        return None
    try:
        payload_b64, sig_b64 = cookie_value.split('.', 1)
        expected_sig = hmac.new(get_signing_key(), payload_b64.encode('ascii'), hashlib.sha256).digest()
        actual_sig = _b64url_decode(sig_b64)

        if not hmac.compare_digest(actual_sig, expected_sig):
            return None

        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))

        exp = payload.get('exp', 0)
        if time.time() > exp:
            return None

        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


async def has_users() -> bool:
    """Check if at least one admin user exists in the database."""
    global _HAS_USERS_CACHE  # pylint: disable=global-statement
    if _HAS_USERS_CACHE:
        return True

    async with db.transaction(readonly=True) as sql:
        count = await sql.value('SELECT count(*) FROM users')
        if count and count > 0:
            _HAS_USERS_CACHE = True
            return True
        return False


def set_users_cache(val: bool = True) -> None:
    global _HAS_USERS_CACHE  # pylint: disable=global-statement
    _HAS_USERS_CACHE = val


async def create_user(username: str, password: str, email: str | None = None) -> str:
    """Create a new local user with hashed password and optional email."""
    user_id = secrets.token_urlsafe(24)
    hashed = hash_password(password)
    clean_email = email.strip().lower() if email and email.strip() else None
    async with db.transaction() as sql:
        await sql.exec(
            'INSERT INTO users (id, username, password_hash, user_type, email) VALUES ($1, $2, $3, $4, $5)',
            user_id,
            username.strip(),
            hashed,
            'local',
            clean_email,
        )
    set_users_cache(True)
    return user_id


async def create_oidc_user(username: str, email: str) -> str:
    """Create a new pre-provisioned OIDC user with mandatory email."""
    user_id = secrets.token_urlsafe(24)
    clean_email = email.strip().lower()
    async with db.transaction() as sql:
        await sql.exec(
            'INSERT INTO users (id, username, password_hash, user_type, email) VALUES ($1, $2, NULL, $3, $4)',
            user_id,
            username.strip(),
            'oidc',
            clean_email,
        )
    set_users_cache(True)
    return user_id


async def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    """Authenticate username and password against database (local accounts only)."""
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            'SELECT id, username, password_hash, user_type, email FROM users WHERE username = $1',
            username.strip(),
        )
    if not record or record['user_type'] != 'local' or not record['password_hash']:
        return None

    if verify_password(password, record['password_hash']):
        # Update last login timestamp
        try:
            async with db.transaction() as sql:
                await sql.exec('UPDATE users SET last_login_at = now() WHERE id = $1', record['id'])
        except Exception as e:  # noqa: BLE001
            logger.warning('Failed to update last_login_at: %s', e)
        return {
            'id': record['id'],
            'username': record['username'],
            'user_type': record['user_type'],
            'email': record['email'],
        }

    return None


async def authenticate_oidc_user(email: str) -> dict[str, Any] | None:
    """Authenticate pre-provisioned OIDC user by verified email."""
    if not email:
        return None
    clean_email = email.strip().lower()
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            'SELECT id, username, user_type, email FROM users WHERE LOWER(email) = $1 AND user_type = $2',
            clean_email,
            'oidc',
        )
    if not record:
        return None

    try:
        async with db.transaction() as sql:
            await sql.exec('UPDATE users SET last_login_at = now() WHERE id = $1', record['id'])
    except Exception as e:  # noqa: BLE001
        logger.warning('Failed to update last_login_at for OIDC user: %s', e)

    return {
        'id': record['id'],
        'username': record['username'],
        'user_type': record['user_type'],
        'email': record['email'],
    }


async def list_users() -> list[dict[str, Any]]:
    """Retrieve all users ordered by creation date."""
    async with db.transaction(readonly=True) as sql:
        records = await sql.conn.fetch(
            'SELECT id, username, user_type, email, created_at, last_login_at FROM users ORDER BY created_at ASC',
        )
    return [dict(r) for r in records]


async def get_user_by_id(user_id: str) -> dict[str, Any] | None:
    """Get single user by ID."""
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            'SELECT id, username, user_type, email, created_at, last_login_at FROM users WHERE id = $1',
            user_id,
        )
    return dict(record) if record else None


async def get_user_by_username(username: str) -> dict[str, Any] | None:
    """Get single user by username."""
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            'SELECT id, username, user_type, email, created_at, last_login_at FROM users WHERE username = $1',
            username.strip(),
        )
    return dict(record) if record else None


async def get_user_by_email(email: str) -> dict[str, Any] | None:
    """Get single user by email."""
    if not email:
        return None
    async with db.transaction(readonly=True) as sql:
        record = await sql.record(
            'SELECT id, username, user_type, email, created_at, last_login_at FROM users WHERE LOWER(email) = $1',
            email.strip().lower(),
        )
    return dict(record) if record else None


async def reset_user_password(user_id: str, new_password: str) -> bool:
    """Reset password for a local user."""
    hashed = hash_password(new_password)
    async with db.transaction() as sql:
        res = await sql.conn.execute(
            "UPDATE users SET password_hash = $1 WHERE id = $2 AND user_type = 'local'",
            hashed,
            user_id,
        )
        return 'UPDATE 1' in res


async def update_user_email(user_id: str, email: str | None) -> bool:
    """Update email for a user."""
    clean_email = email.strip().lower() if email and email.strip() else None
    async with db.transaction() as sql:
        res = await sql.conn.execute(
            'UPDATE users SET email = $1 WHERE id = $2',
            clean_email,
            user_id,
        )
        return 'UPDATE 1' in res


async def count_local_users() -> int:
    """Count number of local users."""
    async with db.transaction(readonly=True) as sql:
        val = await sql.value("SELECT count(*) FROM users WHERE user_type = 'local'")
        return int(val or 0)


async def delete_user(user_id: str, current_username: str) -> tuple[bool, str]:
    """Delete a user with safety checks."""
    user = await get_user_by_id(user_id)
    if not user:
        return False, 'User not found.'

    if user['username'] == current_username:
        return False, 'You cannot delete your own active account.'

    if user['user_type'] == 'local':
        local_count = await count_local_users()
        if local_count <= 1:
            return False, 'Cannot delete the only local administrator account.'

    async with db.transaction() as sql:
        await sql.exec('DELETE FROM users WHERE id = $1', user_id)

    # Invalidate cache if no users remain
    async with db.transaction(readonly=True) as sql:
        count = await sql.value('SELECT count(*) FROM users')
        if not count or count == 0:
            set_users_cache(False)

    return True, ''


async def auto_provision_admin_if_needed() -> bool:
    """Provision admin credentials from environment if configured and not present."""
    if not settings.web.enabled:
        return False

    username = settings.web.admin_username
    password_sec = settings.web.admin_password

    if not username or not password_sec:
        return False

    password = password_sec.get_secret_value()
    if not password:
        return False

    async with db.transaction() as sql:
        existing = await sql.record('SELECT id FROM users WHERE username = $1', username.strip())
        if not existing:
            user_id = secrets.token_urlsafe(24)
            hashed = hash_password(password)
            await sql.exec(
                "INSERT INTO users (id, username, password_hash, user_type) VALUES ($1, $2, $3, 'local')",
                user_id,
                username.strip(),
                hashed,
            )
            set_users_cache(True)
            logger.info('Auto-provisioned web admin user %s from environment.', username)
            return True
        set_users_cache(True)
    return False
