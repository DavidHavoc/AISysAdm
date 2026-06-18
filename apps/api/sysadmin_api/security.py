from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Dict, Optional, Tuple
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from redis import Redis

from .models import LoginResponse, User, utc_now
from .repository import Repository


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class LoginRateLimiter:
    def __init__(
        self,
        redis_client: Optional[Redis] = None,
        maximum_attempts: int = 8,
        window_seconds: int = 300,
    ) -> None:
        self.redis = redis_client
        self.maximum_attempts = maximum_attempts
        self.window_seconds = window_seconds
        self.memory: Dict[str, Tuple[int, float]] = {}

    def allow(self, key: str) -> bool:
        if self.redis:
            redis_key = "login-attempt:%s" % key
            count = int(self.redis.incr(redis_key))
            if count == 1:
                self.redis.expire(redis_key, self.window_seconds)
            return count <= self.maximum_attempts
        now = utc_now().timestamp()
        count, expires = self.memory.get(key, (0, now + self.window_seconds))
        if now >= expires:
            count, expires = 0, now + self.window_seconds
        count += 1
        self.memory[key] = (count, expires)
        return count <= self.maximum_attempts

    def reset(self, key: str) -> None:
        if self.redis:
            self.redis.delete("login-attempt:%s" % key)
        else:
            self.memory.pop(key, None)


class AuthService:
    def __init__(
        self,
        repository: Repository,
        session_ttl_hours: int,
        rate_limiter: LoginRateLimiter,
    ) -> None:
        self.repository = repository
        self.session_ttl_hours = session_ttl_hours
        self.rate_limiter = rate_limiter
        self.passwords = PasswordHasher()

    def ensure_admin(self, username: str, password: str) -> User:
        existing = self.repository.get_user_by_username(username)
        if existing:
            return existing[0]
        user = User(
            id="user-%s" % uuid4().hex[:12],
            username=username,
            created_at=utc_now(),
        )
        return self.repository.save_user(user, self.passwords.hash(password))

    def login(
        self,
        username: str,
        password: str,
        rate_limit_key: str,
    ) -> Tuple[LoginResponse, str]:
        if not self.rate_limiter.allow(rate_limit_key):
            raise ValueError("Too many login attempts. Try again later.")
        record = self.repository.get_user_by_username(username)
        if not record:
            raise ValueError("Invalid username or password")
        user, password_hash = record
        try:
            self.passwords.verify(password_hash, password)
        except VerifyMismatchError as error:
            raise ValueError("Invalid username or password") from error
        self.rate_limiter.reset(rate_limit_key)
        session_token = secrets.token_urlsafe(48)
        csrf_token = secrets.token_urlsafe(32)
        now = utc_now()
        self.repository.save_session(
            session_id="session-%s" % uuid4().hex[:12],
            user_id=user.id,
            token_hash=token_hash(session_token),
            csrf_hash=token_hash(csrf_token),
            expires_at=now + timedelta(hours=self.session_ttl_hours),
            created_at=now,
        )
        return LoginResponse(user=user, csrf_token=csrf_token), session_token

    def authenticate(self, session_token: Optional[str]) -> Optional[User]:
        if not session_token:
            return None
        record = self.repository.get_session(token_hash(session_token))
        if not record or record["expires_at"] <= utc_now():
            return None
        return self.repository.get_user(record["user_id"])

    def verify_csrf(
        self,
        session_token: Optional[str],
        csrf_token: Optional[str],
    ) -> bool:
        if not session_token or not csrf_token:
            return False
        record = self.repository.get_session(token_hash(session_token))
        return bool(
            record
            and hmac.compare_digest(record["csrf_hash"], token_hash(csrf_token))
        )

    def logout(self, session_token: Optional[str]) -> None:
        if session_token:
            self.repository.delete_session(token_hash(session_token))
