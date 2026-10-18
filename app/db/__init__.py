import asyncio
import json
from typing import Any

import asyncpg
from config import settings
from logger import logger
from pydantic import BaseModel

_POOL: asyncpg.pool.Pool = None


async def connect():
    global _POOL  # pylint: disable=global-statement
    _POOL = await asyncpg.create_pool(min_size=0, max_size=20, dsn=str(settings.db_dsn), init=init_connection, server_settings={'application_name': settings.web.app_title})


async def disconnect():
    global _POOL  # pylint: disable=global-statement
    if _POOL is not None:
        pool_loop = getattr(_POOL, '_loop', None)  # pylint: disable=protected-access
        if not _POOL.is_closing() and (pool_loop is None or not pool_loop.is_closed()):
            await _POOL.close()
        _POOL = None


def _is_pool_healthy(pool: asyncpg.pool.Pool | None, current_loop: asyncio.AbstractEventLoop) -> bool:
    if pool is None or pool.is_closing():
        return False
    pool_loop = getattr(pool, '_loop', None)  # pylint: disable=protected-access
    return pool_loop is not None and not pool_loop.is_closed() and pool_loop == current_loop


async def init_connection(conn: asyncpg.Connection):
    await conn.set_type_codec('jsonb', encoder=_encode_json, decoder=json.loads, schema='pg_catalog')


def _encode_json(payload: Any) -> str:
    if isinstance(payload, BaseModel):
        return payload.json()
    else:
        return json.dumps(payload)


class transaction:  # pylint: disable=invalid-name
    readonly = False

    def __init__(self, readonly=False) -> None:
        self.readonly = readonly
        self.conn: asyncpg.Connection = None
        self.trans: asyncpg.connection.transaction = None

    async def __aenter__(self, *args, **kwargs):
        current_loop = asyncio.get_running_loop()
        if not _is_pool_healthy(_POOL, current_loop):
            await connect()
        self.conn = await _POOL.acquire()
        self.trans = self.conn.transaction(readonly=self.readonly)
        await self.trans.start()
        return self

    async def __call__(self, *args):
        """fetch response for query"""
        async for rec in self.conn.cursor(*args):
            yield rec

    async def record(self, *args):
        """fetch first response row for query"""
        return await self.conn.fetchrow(*args)

    async def value(self, *args):
        """fetch first value from first response row for query"""
        return await self.conn.fetchval(*args)

    async def exec(self, *args):  # noqa: A003 (allow shadowing builtin "type")
        """execute command"""
        return await self.conn.execute(*args)

    async def execmany(self, command: str, *args):
        """execute command with many records"""
        return await self.conn.executemany(command, args)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            logger.debug('Transaction rollback. Reason: %s %s %s', exc_type, exc_val, exc_tb)
            await self.trans.rollback()
        else:
            await self.trans.commit()
        await _POOL.release(self.conn)
