import json
from abc import ABC, abstractmethod
from typing import Dict, Optional

from redis import Redis


class AgentMemory(ABC):
    @abstractmethod
    def put(self, key: str, value: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def get(self, key: str) -> Optional[str]:
        raise NotImplementedError


class InMemoryAgentMemory(AgentMemory):
    def __init__(self) -> None:
        self._values: Dict[str, str] = {}

    def put(self, key: str, value: str) -> None:
        self._values[key] = value

    def get(self, key: str) -> Optional[str]:
        return self._values.get(key)


class RedisAgentMemory(AgentMemory):
    """Short-lived AI context only. PostgreSQL remains the audit source of truth."""

    def __init__(self, redis_url: str, ttl_seconds: int) -> None:
        self._client = Redis.from_url(redis_url, decode_responses=True)
        self._ttl_seconds = ttl_seconds

    def put(self, key: str, value: str) -> None:
        self._client.setex(key, self._ttl_seconds, json.dumps({"value": value}))

    def get(self, key: str) -> Optional[str]:
        payload = self._client.get(key)
        if payload is None:
            return None
        return str(json.loads(payload)["value"])
