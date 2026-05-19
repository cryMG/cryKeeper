from ipaddress import ip_address, ip_network


_FORWARDED_HEADER_KEYS = (
  "HTTP_FORWARDED",
  "HTTP_X_FORWARDED_FOR",
  "HTTP_X_FORWARDED_HOST",
  "HTTP_X_FORWARDED_PORT",
  "HTTP_X_FORWARDED_PREFIX",
  "HTTP_X_FORWARDED_PROTO",
  "HTTP_X_REAL_IP",
)


class TrustedProxyHeadersMiddleware:
  """Strip forwarded headers unless the direct peer belongs to a trusted proxy network."""

  def __init__(self, app, trusted_proxy_cidrs: tuple[str, ...]) -> None:
    self._app = app
    self._trusted_networks = tuple(
      ip_network(value, strict=False) for value in trusted_proxy_cidrs
    )

  def __call__(self, environ, start_response):
    if not self._remote_addr_is_trusted(environ.get("REMOTE_ADDR")):
      for header_name in _FORWARDED_HEADER_KEYS:
        environ.pop(header_name, None)
    return self._app(environ, start_response)

  def _remote_addr_is_trusted(self, value: str | None) -> bool:
    if value is None:
      return False

    candidate = value.strip()
    if not candidate:
      return False

    try:
      remote_ip = ip_address(candidate)
    except ValueError:
      return False

    return any(remote_ip in network for network in self._trusted_networks)
