"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import json
from typing import Optional
from uuid import UUID, uuid4

# Related third party imports
import redis

# Local application imports
from faraday.server.config import faraday_server
from faraday.server.debouncer import get_redis_client

EXECUTOR_CONFIG_TTL = 300


def valid_request_id(request_id) -> bool:
    try:
        return str(UUID(str(request_id))) == str(request_id)
    except ValueError:
        return False


def redis_key(agent_id: int, request_id: str) -> str:
    prefix = faraday_server.celery_queue_prefix
    return ':'.join(part for part in (prefix, 'agent_config', str(agent_id), request_id) if part)


def create_request(agent_id: int) -> str:
    request_id = str(uuid4())
    get_redis_client().set(redis_key(agent_id, request_id),
                           json.dumps({'status': 'pending', 'agent_id': agent_id}),
                           ex=EXECUTOR_CONFIG_TTL)
    return request_id


def delete_request(agent_id: int, request_id: str) -> None:
    get_redis_client().delete(redis_key(agent_id, request_id))


def get_request(agent_id: int, request_id: str) -> Optional[dict]:
    if not valid_request_id(request_id):
        return None
    raw = get_redis_client().get(redis_key(agent_id, request_id))
    return json.loads(raw) if raw else None


def finish_request(agent_id: int, request_id: str, successful: bool, message: str) -> bool:
    """Stores the result of a pending request, keeping its TTL. Only the status and the message are stored.

    The check of the pending status and the write are one transaction: if the key changes in between (e.g. an
    overlapping reply), nothing is written.
    """
    if not valid_request_id(request_id):
        return False
    key = redis_key(agent_id, request_id)
    result = json.dumps({'status': 'ok' if successful else 'error', 'agent_id': agent_id, 'message': message})
    with get_redis_client().pipeline() as pipe:
        try:
            pipe.watch(key)
            raw = pipe.get(key)
            current = json.loads(raw) if raw else None
            if current is None or current.get('agent_id') != agent_id or current.get('status') != 'pending':
                return False
            pipe.multi()
            pipe.set(key, result, keepttl=True)
            pipe.execute()
        except redis.WatchError:
            return False
    return True
