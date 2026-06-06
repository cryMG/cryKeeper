import unittest
from unittest.mock import MagicMock, patch

from app.ratelimit import (
  FallbackRateLimiter,
  InMemoryRateLimiter,
  RateLimitBackendFailure,
  RateLimitRule,
  ValkeyRateLimiter,
  WebsiteRateLimiter,
)
from redis.exceptions import RedisError


class InMemoryRateLimiterTests(unittest.TestCase):
  def test_check_returns_allowed_for_disabled_rule(self):
    """Test that disabled rules always return allowed."""
    limiter = InMemoryRateLimiter()
    rule = RateLimitRule(max_requests=0, window_seconds=10, block_seconds=5)

    result = limiter.check("test-key", rule)

    self.assertTrue(result.allowed)
    self.assertIsNone(result.retry_after_seconds)

  def test_check_returns_blocked_when_blocked(self):
    """Test that blocked requests return blocked decision."""
    limiter = InMemoryRateLimiter()
    rule = RateLimitRule(max_requests=1, window_seconds=10, block_seconds=5)

    # First request should be allowed
    result1 = limiter.check("test-key", rule)
    self.assertTrue(result1.allowed)

    # Second request should trigger blocking
    result2 = limiter.check("test-key", rule)
    self.assertFalse(result2.allowed)
    self.assertIsNotNone(result2.retry_after_seconds)


class ValkeyRateLimiterTests(unittest.TestCase):
  @patch("app.ratelimit.redis.Redis.from_url")
  def test_check_returns_allowed_for_disabled_rule(self, mock_redis):
    mock_client = MagicMock()
    mock_redis.return_value = mock_client
    mock_client.register_script.return_value = MagicMock(return_value=[1, 0])

    limiter = ValkeyRateLimiter.from_url("redis://localhost", "test")
    rule = RateLimitRule(max_requests=0, window_seconds=10, block_seconds=5)

    result = limiter.check("test-key", rule)

    self.assertTrue(result.allowed)

  @patch("app.ratelimit.redis.Redis.from_url")
  def test_check_raises_backend_failure_on_redis_error(self, mock_redis):
    mock_client = MagicMock()
    mock_redis.return_value = mock_client
    mock_client.register_script.return_value = MagicMock(
      side_effect=RedisError("Connection failed")
    )

    limiter = ValkeyRateLimiter.from_url("redis://localhost", "test")
    rule = RateLimitRule(max_requests=10, window_seconds=10, block_seconds=5)

    with self.assertRaises(RateLimitBackendFailure):
      limiter.check("test-key", rule)


class FallbackRateLimiterTests(unittest.TestCase):
  def test_check_falls_back_to_memory_on_backend_failure(self):
    """Test that backend failures trigger fallback to in-memory limiter."""
    primary = MagicMock()
    primary.check.side_effect = RateLimitBackendFailure("Backend failed")
    fallback = InMemoryRateLimiter()
    logger = MagicMock()

    limiter = FallbackRateLimiter(primary, fallback, logger)
    rule = RateLimitRule(max_requests=10, window_seconds=10, block_seconds=5)

    result = limiter.check("test-key", rule)

    # Should fallback to memory limiter
    self.assertIsNotNone(result)

  def test_check_calls_backend_failure_callback(self):
    """Test that backend failure callback is called when configured."""
    primary = MagicMock()
    primary.check.side_effect = RateLimitBackendFailure("Backend failed")
    fallback = InMemoryRateLimiter()
    logger = MagicMock()
    callback = MagicMock()

    limiter = FallbackRateLimiter(
      primary, fallback, logger, backend_failure_callback=callback
    )
    rule = RateLimitRule(max_requests=10, window_seconds=10, block_seconds=5)

    limiter.check("test-key", rule)

    callback.assert_called_once_with("valkey")

  def test_check_logs_backend_failure_with_rate_limiting(self):
    """Test that backend failures are logged with rate limiting."""
    primary = MagicMock()
    primary.check.side_effect = RateLimitBackendFailure("Backend failed")
    fallback = InMemoryRateLimiter()
    logger = MagicMock()

    limiter = FallbackRateLimiter(primary, fallback, logger)
    rule = RateLimitRule(max_requests=10, window_seconds=10, block_seconds=5)

    # First call should log
    limiter.check("test-key", rule)
    logger.warning.assert_called_once()

    # Second call within 60 seconds should not log
    logger.warning.reset_mock()
    limiter.check("test-key", rule)
    logger.warning.assert_not_called()


class WebsiteRateLimiterTests(unittest.TestCase):
  def test_init_raises_error_when_valkey_required_but_not_provided(self):
    """Test that RuntimeError is raised when valkey URL is missing."""
    logger = MagicMock()

    with self.assertRaises(RuntimeError) as context:
      WebsiteRateLimiter(
        backend="valkey",
        valkey_url="",
        key_prefix="test",
        max_entries=1000,
        logger=logger,
      )

    self.assertIn(
      "rate_limit_backend=valkey requires rate_limit_valkey_url", str(context.exception)
    )

  def test_metrics_backend_name_returns_memory_for_memory_backend(self):
    """Test that metrics_backend_name returns 'memory' for memory backend."""
    logger = MagicMock()
    limiter = WebsiteRateLimiter(
      backend="memory",
      valkey_url="",
      key_prefix="test",
      max_entries=1000,
      logger=logger,
    )

    self.assertEqual("memory", limiter.metrics_backend_name)

  def test_metrics_backend_name_returns_valkey_for_valkey_backend(self):
    """Test that metrics_backend_name returns 'valkey' for valkey backend."""
    logger = MagicMock()
    limiter = WebsiteRateLimiter(
      backend="valkey",
      valkey_url="redis://localhost",
      key_prefix="test",
      max_entries=1000,
      logger=logger,
    )

    self.assertEqual("valkey", limiter.metrics_backend_name)


if __name__ == "__main__":
  unittest.main()
