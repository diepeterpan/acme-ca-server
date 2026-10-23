"""API Trace management, logging, and retrieval module."""

from __future__ import annotations

import json
import secrets
from datetime import datetime
from typing import Any

import db
from config import settings
from logger import logger
from pydantic import BaseModel


class ApiTraceEntry(BaseModel):
    id: str  # noqa: A003
    timestamp: datetime
    client_ip: str
    target_host: str
    http_method: str
    endpoint: str
    status_code: int
    duration_ms: int
    request_headers: dict[str, Any] = {}
    request_payload: str = ''
    response_headers: dict[str, Any] = {}
    response_payload: str = ''
    error_message: str | None = None


_api_trace_enabled_cache: bool | None = None  # pylint: disable=invalid-name


async def is_api_trace_enabled() -> bool:
    """Return whether API tracing is currently enabled, consulting DB with fallback to settings."""
    global _api_trace_enabled_cache  # pylint: disable=global-statement
    if _api_trace_enabled_cache is not None:
        return _api_trace_enabled_cache

    try:
        async with db.transaction(readonly=True) as sql:
            val = await sql.value('SELECT enabled FROM api_trace_settings WHERE dummy_id = 1')
            if val is not None:
                _api_trace_enabled_cache = bool(val)
                return _api_trace_enabled_cache
    except Exception as exc:  # noqa: BLE001
        logger.debug('Could not read api_trace_settings from DB: %s', exc)

    # If row does not exist in DB yet, seed it with settings
    seed_val = bool(settings.api_trace.enabled)
    try:
        async with db.transaction() as sql:
            await sql.exec(
                """
                INSERT INTO api_trace_settings (dummy_id, enabled)
                VALUES (1, $1)
                ON CONFLICT (dummy_id) DO NOTHING
                """,
                seed_val,
            )
            val = await sql.value('SELECT enabled FROM api_trace_settings WHERE dummy_id = 1')
            _api_trace_enabled_cache = bool(val if val is not None else seed_val)
            return _api_trace_enabled_cache
    except Exception as exc:  # noqa: BLE001
        logger.debug('Could not initialize api_trace_settings row: %s', exc)
        _api_trace_enabled_cache = seed_val
        return _api_trace_enabled_cache


async def set_api_trace_enabled(enabled: bool, delete_logs: bool = False) -> None:
    """Toggle API tracing on/off and optionally clear logs when disabled."""
    global _api_trace_enabled_cache  # pylint: disable=global-statement
    async with db.transaction() as sql:
        await sql.exec(
            """
            INSERT INTO api_trace_settings (dummy_id, enabled, updated_at)
            VALUES (1, $1, now())
            ON CONFLICT (dummy_id) DO UPDATE SET enabled = $1, updated_at = now()
            """,
            enabled,
        )
        if not enabled and delete_logs:
            await sql.exec('DELETE FROM api_traces')
    _api_trace_enabled_cache = enabled


async def clear_all_traces() -> int:
    """Delete all logged API traces."""
    async with db.transaction() as sql:
        res = await sql.exec('DELETE FROM api_traces')
        # Try to parse row count if asyncpg returns format 'DELETE <n>'
        try:
            return int(str(res).split()[-1])
        except Exception:  # noqa: BLE001
            return 0


async def record_trace(
    *,
    client_ip: str,
    target_host: str,
    http_method: str,
    endpoint: str,
    status_code: int,
    duration_ms: int,
    request_headers: dict[str, Any],
    request_payload: str,
    response_headers: dict[str, Any],
    response_payload: str,
    error_message: str | None = None,
) -> None:
    """Insert an API trace record asynchronously."""
    # Generate unique 24-character random_id compatible with db random_id domain
    trace_id = f'trc_{secrets.token_hex(16)}'
    try:
        async with db.transaction() as sql:
            await sql.exec(
                """
                INSERT INTO api_traces (
                    id, client_ip, target_host, http_method, endpoint,
                    status_code, duration_ms, request_headers, request_payload,
                    response_headers, response_payload, error_message
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                """,
                trace_id,
                client_ip,
                target_host,
                http_method,
                endpoint,
                status_code,
                duration_ms,
                json.dumps(request_headers),
                request_payload,
                json.dumps(response_headers),
                response_payload,
                error_message,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning('Failed to record API trace: %s', exc)


async def get_traces(limit: int = 500, offset: int = 0, search: str = '') -> list[dict[str, Any]]:
    """Retrieve API traces for the web dashboard."""
    query = """
        SELECT id, timestamp, client_ip, target_host, http_method, endpoint,
               status_code, duration_ms, request_payload, response_payload, error_message
        FROM api_traces
    """
    params: list[Any] = []
    if search:
        query += """
            WHERE endpoint ILIKE $1
               OR client_ip ILIKE $1
               OR http_method ILIKE $1
               OR target_host ILIKE $1
        """
        params.append(f'%{search.strip()}%')

    query += ' ORDER BY timestamp DESC'
    if params:
        query += f' LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}'
        params.extend([limit, offset])
    else:
        query += ' LIMIT $1 OFFSET $2'
        params.extend([limit, offset])

    async with db.transaction(readonly=True) as sql:
        rows = await sql.fetch(query, *params)
        return [dict(r) for r in rows] if rows else []


async def get_new_traces(after_timestamp: datetime | None = None, exclude_id: str = '', search: str = '', limit: int = 100) -> list[dict[str, Any]]:
    """Retrieve new traces created after after_timestamp, ordered by timestamp ASC for prepending."""
    if not after_timestamp:
        return []

    query = """
        SELECT id, timestamp, client_ip, target_host, http_method, endpoint,
               status_code, duration_ms, request_payload, response_payload, error_message
        FROM api_traces
        WHERE timestamp >= $1
    """
    params: list[Any] = [after_timestamp]

    if exclude_id:
        query += f' AND id != ${len(params) + 1}'
        params.append(exclude_id)

    if search:
        query += f"""
            AND (endpoint ILIKE ${len(params) + 1}
               OR client_ip ILIKE ${len(params) + 1}
               OR http_method ILIKE ${len(params) + 1}
               OR target_host ILIKE ${len(params) + 1})
        """
        params.append(f'%{search.strip()}%')

    query += f' ORDER BY timestamp ASC LIMIT ${len(params) + 1}'
    params.append(limit)

    async with db.transaction(readonly=True) as sql:
        rows = await sql.fetch(query, *params)
        return [dict(r) for r in rows] if rows else []



async def get_trace_count(search: str = '') -> int:
    """Return total count of traces matching search."""
    query = 'SELECT count(*) FROM api_traces'
    params: list[Any] = []
    if search:
        query += """
            WHERE endpoint ILIKE $1
               OR client_ip ILIKE $1
               OR http_method ILIKE $1
               OR target_host ILIKE $1
        """
        params.append(f'%{search.strip()}%')

    async with db.transaction(readonly=True) as sql:
        val = await sql.value(query, *params)
        return int(val) if val is not None else 0


async def get_trace_payload(trace_id: str) -> dict[str, Any] | None:
    """Retrieve complete payload details for a single trace entry."""
    async with db.transaction(readonly=True) as sql:
        row = await sql.record(
            """
            SELECT id, timestamp, client_ip, target_host, http_method, endpoint,
                   status_code, duration_ms, request_headers, request_payload,
                   response_headers, response_payload, error_message
            FROM api_traces
            WHERE id = $1
            """,
            trace_id,
        )
        if not row:
            return None
        res = dict(row)
        if isinstance(res.get('request_headers'), str):
            try:
                res['request_headers'] = json.loads(res['request_headers'])
            except Exception as exc:  # noqa: BLE001
                logger.debug('Could not decode request_headers JSON: %s', exc)
        if isinstance(res.get('response_headers'), str):
            try:
                res['response_headers'] = json.loads(res['response_headers'])
            except Exception as exc:  # noqa: BLE001
                logger.debug('Could not decode response_headers JSON: %s', exc)
        return res
