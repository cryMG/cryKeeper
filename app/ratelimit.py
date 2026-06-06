import hashlib
import math
import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Callable

import redis
from redis.exceptions import RedisError


@dataclass(frozen=True)
class RateLimitRule:
  """Configuration for a simple in-memory request budget."""

  max_requests: int
  window_seconds: int
  block_seconds: int

  @property
  def enabled(self) -> bool:
    return self.max_requests > 0 and self.window_seconds > 0 and self.block_seconds > 0


@dataclass(frozen=True)
class RateLimitDecision:
  """Result of a rate-limit check."""

  allowed: bool
  retry_after_seconds: int | None = None


class RateLimitBackendFailure(Exception):
  """Structured backend errors used to trigger resilient fallbacks."""

  def __init__(self, message: str):
    self.message = message
    super().__init__(message)


@dataclass
class _BucketState:
  """Mutable state tracked per client bucket."""

  request_times: deque[float] = field(default_factory=deque)
  blocked_until: float = 0.0
  strikes: int = 0
  last_seen: float = 0.0


_VALKEY_RATE_LIMIT_SCRIPT = """
local max_requests = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local block_ms = tonumber(ARGV[3])
local now_ms = tonumber(ARGV[4])
local retention_ms = tonumber(ARGV[5])

if max_requests <= 0 or window_ms <= 0 or block_ms <= 0 then
    return {1, 0}
end

local block_ttl_ms = redis.call('PTTL', KEYS[2])
if block_ttl_ms ~= false and block_ttl_ms > 0 then
    return {0, block_ttl_ms}
end

redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now_ms - window_ms)
local request_count = redis.call('ZCARD', KEYS[1])

if request_count >= max_requests then
    local strikes = redis.call('INCR', KEYS[3])
    redis.call('PEXPIRE', KEYS[3], retention_ms)

    local penalty_ms = block_ms
    local max_penalty_ms = block_ms * 8
    local exponent = strikes - 1
    while exponent > 0 and penalty_ms < max_penalty_ms do
        penalty_ms = penalty_ms * 2
        exponent = exponent - 1
    end
    if penalty_ms > max_penalty_ms then
        penalty_ms = max_penalty_ms
    end

    redis.call('PSETEX', KEYS[2], penalty_ms, '1')
    redis.call('DEL', KEYS[1])
    return {0, penalty_ms}
end

local sequence = redis.call('INCR', KEYS[4])
redis.call('PEXPIRE', KEYS[4], retention_ms)
local member = tostring(now_ms) .. '-' .. tostring(sequence)
redis.call('ZADD', KEYS[1], now_ms, member)
redis.call('PEXPIRE', KEYS[1], retention_ms)
return {1, 0}
"""


class InMemoryRateLimiter:
  """Best-effort process-local limiter for public crykeeper endpoints."""

  def __init__(self, max_entries: int = 10000) -> None:
    self._max_entries = max_entries
    self._lock = Lock()
    self._states: dict[str, _BucketState] = {}
    self._checks = 0

  def check(self, key: str, rule: RateLimitRule) -> RateLimitDecision:
    if not rule.enabled:
      return RateLimitDecision(allowed=True)

    now = time.monotonic()
    with self._lock:
      self._checks += 1
      if self._checks % 128 == 0:
        self._prune_locked(now, rule)

      state = self._states.setdefault(key, _BucketState())
      state.last_seen = now

      if state.blocked_until > now:
        return RateLimitDecision(
          allowed=False,
          retry_after_seconds=math.ceil(state.blocked_until - now),
        )

      cutoff = now - rule.window_seconds
      while state.request_times and state.request_times[0] <= cutoff:
        state.request_times.popleft()

      if not state.request_times:
        state.strikes = 0

      if len(state.request_times) >= rule.max_requests:
        state.strikes = min(state.strikes + 1, 5)
        penalty_seconds = min(
          rule.block_seconds * (2 ** (state.strikes - 1)),
          rule.block_seconds * 8,
        )
        state.blocked_until = now + penalty_seconds
        state.request_times.clear()
        return RateLimitDecision(
          allowed=False,
          retry_after_seconds=math.ceil(penalty_seconds),
        )

      state.request_times.append(now)
      return RateLimitDecision(allowed=True)

  def _prune_locked(self, now: float, rule: RateLimitRule) -> None:
    if len(self._states) <= self._max_entries:
      return

    retention_seconds = max(rule.window_seconds, rule.block_seconds * 8, 300)
    stale_keys = [
      key
      for key, state in self._states.items()
      if state.blocked_until <= now and now - state.last_seen > retention_seconds
    ]
    for key in stale_keys:
      del self._states[key]

    if len(self._states) <= self._max_entries:
      return

    overflow = len(self._states) - self._max_entries
    oldest_keys = sorted(self._states, key=lambda key: self._states[key].last_seen)[
      :overflow
    ]
    for key in oldest_keys:
      del self._states[key]


class ValkeyRateLimiter:
  """Distributed rate limiter backed by Valkey/Redis."""

  def __init__(self, client: redis.Redis, key_prefix: str = "crykeeper:rl") -> None:
    self._client = client
    self._key_prefix = key_prefix.rstrip(":") or "crykeeper:rl"
    self._script = client.register_script(_VALKEY_RATE_LIMIT_SCRIPT)

  @classmethod
  def from_url(cls, url: str, key_prefix: str) -> "ValkeyRateLimiter":
    client = redis.Redis.from_url(url)
    return cls(client, key_prefix=key_prefix)

  def check(self, key: str, rule: RateLimitRule) -> RateLimitDecision:
    if not rule.enabled:
      return RateLimitDecision(allowed=True)

    now_ms = int(time.time() * 1000)
    retention_ms = max(rule.window_seconds, rule.block_seconds * 8, 300) * 1000
    keys = self._keys_for(key)

    try:
      result = self._script(
        keys=keys,
        args=[
          rule.max_requests,
          rule.window_seconds * 1000,
          rule.block_seconds * 1000,
          now_ms,
          retention_ms,
        ],
      )
    except RedisError as exc:
      raise RateLimitBackendFailure(str(exc)) from exc

    allowed = bool(int(result[0]))
    retry_after_ms = int(result[1]) if len(result) > 1 else 0
    if allowed:
      return RateLimitDecision(allowed=True)

    return RateLimitDecision(
      allowed=False,
      retry_after_seconds=max(1, math.ceil(retry_after_ms / 1000)),
    )

  def _keys_for(self, key: str) -> list[str]:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    base_key = f"{self._key_prefix}:{digest}"
    return [
      f"{base_key}:requests",
      f"{base_key}:block",
      f"{base_key}:strikes",
      f"{base_key}:sequence",
    ]


class FallbackRateLimiter:
  """Use Valkey when available and fall back to local memory on backend failures."""

  def __init__(
    self,
    primary: ValkeyRateLimiter,
    fallback: InMemoryRateLimiter,
    logger,
    backend_failure_callback: Callable[[str], None] | None = None,
  ) -> None:
    self._primary = primary
    self._fallback = fallback
    self._logger = logger
    self._last_error_log_at = 0.0
    self._backend_failure_callback = backend_failure_callback

  def check(self, key: str, rule: RateLimitRule) -> RateLimitDecision:
    try:
      return self._primary.check(key, rule)
    except RateLimitBackendFailure as exc:
      self._log_backend_failure(exc)
      return self._fallback.check(key, rule)

  def _log_backend_failure(self, exc: RateLimitBackendFailure) -> None:
    if self._backend_failure_callback is not None:
      self._backend_failure_callback("valkey")

    now = time.monotonic()
    if now - self._last_error_log_at < 60:
      return

    self._last_error_log_at = now
    self._logger.warning(
      "Rate limiter backend failed, falling back to in-memory limits",
      extra={"backend_error": exc.message},
    )


class WebsiteRateLimiter:
  """Resolve the shared backend once while keeping website buckets separated by key."""

  def __init__(
    self,
    backend: str,
    valkey_url: str,
    key_prefix: str,
    max_entries: int,
    logger,
    backend_failure_callback: Callable[[str], None] | None = None,
  ) -> None:
    self._backend = backend
    self._valkey_url = (valkey_url or "").strip()
    self._memory_limiter = InMemoryRateLimiter(max_entries)
    self._shared_limiter: FallbackRateLimiter | None = None

    if backend == "memory":
      return

    if backend == "auto" and not self._valkey_url:
      return

    if not self._valkey_url:
      raise RuntimeError(
        "rate_limit_backend=valkey requires rate_limit_valkey_url "
        "or shared rate_limit_valkey_url under [crykeeper]."
      )

    primary = ValkeyRateLimiter.from_url(self._valkey_url, key_prefix)
    self._shared_limiter = FallbackRateLimiter(
      primary,
      InMemoryRateLimiter(max_entries),
      logger,
      backend_failure_callback=backend_failure_callback,
    )

  def check(self, key: str, rule: RateLimitRule) -> RateLimitDecision:
    if self._shared_limiter is None:
      return self._memory_limiter.check(key, rule)
    return self._shared_limiter.check(key, rule)

  @property
  def metrics_backend_name(self) -> str:
    if self._shared_limiter is None:
      return "memory"
    return "valkey"


def create_rate_limiter(
  settings_source: object,
  logger,
  backend_failure_callback: Callable[[str], None] | None = None,
) -> WebsiteRateLimiter:
  """Build the shared rate-limit backend with one global Valkey URL if configured."""
  settings = getattr(settings_source, "default_settings", settings_source)
  return WebsiteRateLimiter(
    settings.rate_limit_backend,
    settings.rate_limit_valkey_url,
    settings.rate_limit_valkey_prefix,
    settings.rate_limit_max_entries,
    logger,
    backend_failure_callback=backend_failure_callback,
  )
