"""ACME CA Server - User Password Reset Tool.

Interactive administrative utility to safely retrieve, select, and reset
user passwords directly in the PostgreSQL database.
"""

# pylint: disable=duplicate-code

import argparse
import asyncio
import getpass
import sys
from typing import Any

import db
from logger import logger
from web.auth import hash_password

# Terminal color formatting
COLOR_CYAN_BOLD = '\033[1;36m'
COLOR_GREEN_BOLD = '\033[1;32m'
COLOR_YELLOW = '\033[1;33m'
COLOR_YELLOW_BOLD = '\033[1;33m'
COLOR_RED_BOLD = '\033[1;31m'
COLOR_DIM = '\033[2m'
COLOR_BOLD = '\033[1m'
COLOR_RESET = '\033[0m'


def _print(msg: str = '') -> None:
    """Print message to stdout without triggering flake8 print check."""
    sys.stdout.write(f'{msg}\n')
    sys.stdout.flush()


def _print_raw(msg: str) -> None:
    """Print raw message to stdout without trailing newline."""
    sys.stdout.write(msg)
    sys.stdout.flush()


async def get_all_users() -> list[dict[str, Any]]:
    """Retrieve all users from database ordered by creation date."""
    async with db.transaction(readonly=True) as sql:
        records = await sql.conn.fetch(
            'SELECT id, username, user_type, email, created_at, last_login_at FROM users ORDER BY created_at ASC',
        )
    return [dict(r) for r in records]


async def select_and_confirm_user(target_arg: str | None = None) -> str | None:
    """Retrieve users, interactively select target user if needed, and confirm selection."""
    users = await get_all_users()

    if not users:
        _print(f'{COLOR_RED_BOLD}[!] No users found in database.{COLOR_RESET}')
        _print(f'{COLOR_DIM}    Tip: Access the web interface at /setup or configure WEB_ADMIN_USERNAME/PASSWORD.{COLOR_RESET}\n')
        return None

    selected_user: dict[str, Any] | None = None

    # 1. Target passed via CLI argument
    if target_arg:
        matching = [u for u in users if u['username'].lower() == target_arg.strip().lower()]
        if not matching:
            _print(f"{COLOR_RED_BOLD}[!] User '{target_arg}' does not exist in the database.{COLOR_RESET}")
            _print(f'{COLOR_DIM}    Available users: {", ".join(u["username"] for u in users)}{COLOR_RESET}\n')
            return None
        selected_user = matching[0]

    # 2. Single user in database
    elif len(users) == 1:
        u = users[0]
        selected_user = u
        last_login = u['last_login_at'].strftime('%Y-%m-%d %H:%M:%S UTC') if u['last_login_at'] else 'Never'
        created_str = u['created_at'].strftime('%Y-%m-%d')
        u_type = u.get('user_type', 'local').upper()
        _print(
            f'{COLOR_CYAN_BOLD}[*] Found user:{COLOR_RESET} {COLOR_BOLD}{u["username"]}{COLOR_RESET} '
            f'[{u_type}] {COLOR_DIM}(Created: {created_str}, Last login: {last_login}){COLOR_RESET}'
        )

    # 3. Multiple users in database - display interactive selection menu
    else:
        _print(f'{COLOR_CYAN_BOLD}[*] Registered users in database:{COLOR_RESET}')
        for idx, u in enumerate(users, start=1):
            last_login = u['last_login_at'].strftime('%Y-%m-%d %H:%M:%S UTC') if u['last_login_at'] else 'Never'
            u_type = u.get('user_type', 'local').upper()
            _print(f'  {COLOR_BOLD}[{idx}]{COLOR_RESET} {u["username"]:<18} [{u_type:<5}] {COLOR_DIM}Last login: {last_login}{COLOR_RESET}')

        while True:
            _print_raw(f'\n{COLOR_YELLOW_BOLD}--> Select user number [1-{len(users)}] or enter username [1]: {COLOR_RESET}')
            choice = sys.stdin.readline().strip()
            if not choice or choice == '1':
                selected_user = users[0]
                break
            if choice.isdigit() and 1 <= int(choice) <= len(users):
                selected_user = users[int(choice) - 1]
                break
            matched = [u for u in users if u['username'].lower() == choice.lower()]
            if matched:
                selected_user = matched[0]
                break
            _print(f"{COLOR_RED_BOLD}Invalid selection '{choice}'. Please select a valid number or username.{COLOR_RESET}")

    if not selected_user:
        return None

    if selected_user.get('user_type') == 'oidc':
        _print(f"{COLOR_RED_BOLD}[!] User '{selected_user['username']}' is an OIDC user ({selected_user.get('email')}).{COLOR_RESET}")
        _print(f'{COLOR_DIM}    Passwords for OIDC users must be managed at your identity provider (e.g., Authelia).{COLOR_RESET}\n')
        return None

    selected_username = selected_user['username']

    # Explicit confirmation of target username
    _print_raw(f"{COLOR_YELLOW_BOLD}--> Confirm password reset for local user '{selected_username}'? [Y/n]: {COLOR_RESET}")
    confirm_reply = sys.stdin.readline().strip().lower()
    if confirm_reply and confirm_reply not in ('y', 'yes'):
        _print(f'{COLOR_DIM}[*] Password reset cancelled by operator.{COLOR_RESET}\n')
        return None

    return selected_username


def prompt_for_new_password() -> str | None:
    """Prompt for new password twice using masked terminal input."""
    while True:
        try:
            pwd1 = getpass.getpass(f'{COLOR_BOLD}Enter new password (min 8 chars): {COLOR_RESET}')
        except (KeyboardInterrupt, EOFError):
            _print(f'\n{COLOR_DIM}[*] Cancelled.{COLOR_RESET}')
            return None

        if len(pwd1) < 8:
            _print(f'{COLOR_RED_BOLD}[!] Password must be at least 8 characters long.{COLOR_RESET}')
            continue

        try:
            pwd2 = getpass.getpass(f'{COLOR_BOLD}Confirm new password: {COLOR_RESET}')
        except (KeyboardInterrupt, EOFError):
            _print(f'\n{COLOR_DIM}[*] Cancelled.{COLOR_RESET}')
            return None

        if pwd1 != pwd2:
            _print(f'{COLOR_RED_BOLD}[!] Passwords do not match. Please try again.{COLOR_RESET}\n')
            continue

        return pwd1


async def reset_user_password(username: str, new_password: str) -> bool:
    """Hash new password and update user in database."""
    hashed = hash_password(new_password)
    async with db.transaction() as sql:
        result = await sql.conn.execute(
            "UPDATE users SET password_hash = $1 WHERE username = $2 AND user_type = 'local'",
            hashed,
            username,
        )
    return 'UPDATE 1' in result


async def run_reset_password_workflow(target_username: str | None = None) -> int:
    """Execute complete password reset workflow."""
    _print(f'\n{COLOR_CYAN_BOLD}======================================================{COLOR_RESET}')
    _print(f'{COLOR_CYAN_BOLD}        ACME CA SERVER - USER PASSWORD RESET{COLOR_RESET}')
    _print(f'{COLOR_CYAN_BOLD}======================================================{COLOR_RESET}\n')

    try:
        username = await select_and_confirm_user(target_username)
        if not username:
            return 1

        _print()
        new_password = prompt_for_new_password()
        if not new_password:
            return 1

        _print(f"\n{COLOR_CYAN_BOLD}[*] Updating password for user '{username}' in database...{COLOR_RESET}")
        success = await reset_user_password(username, new_password)
        if success:
            _print(f"{COLOR_GREEN_BOLD}[✓] Password for user '{username}' successfully updated!{COLOR_RESET}\n")
            return 0
        else:
            _print(f"{COLOR_RED_BOLD}[!] Failed to update password for user '{username}'.{COLOR_RESET}\n")
            return 1

    except Exception as exc:  # noqa: BLE001
        logger.error('Error during password reset: %s', exc)
        _print(f'{COLOR_RED_BOLD}[!] Error during password reset: {exc}{COLOR_RESET}\n')
        return 1
    finally:
        await db.disconnect()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='ACME CA Server - Database User Password Reset Utility',
    )
    parser.add_argument(
        'user',
        nargs='?',
        default=None,
        help='Optional username to reset. If omitted, prompts interactively.',
    )
    args = parser.parse_args()

    try:
        exit_code = asyncio.run(run_reset_password_workflow(args.user))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        _print(f'\n{COLOR_DIM}[*] Operation cancelled by user.{COLOR_RESET}')
        sys.exit(130)


if __name__ == '__main__':
    main()
