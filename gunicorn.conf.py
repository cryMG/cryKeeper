from ipaddress import ip_address, ip_network

from app.config import load_settings_bundle
from gunicorn import glogging
from prometheus_client import multiprocess

SETTINGS_BUNDLE = load_settings_bundle()


def _anonymized_access_log_ip(value: str) -> str:
  """Reduce logged IP precision while keeping coarse subnet context."""
  try:
    parsed_ip = ip_address(value)
  except ValueError:
    return value

  if parsed_ip.is_loopback:
    # don't anonymize loopback addresses, since they don't represent real clients
    return parsed_ip.compressed

  prefix_length = 24 if parsed_ip.version == 4 else 48
  return ip_network(f"{parsed_ip.compressed}/{prefix_length}", strict=False).compressed


def access_log_remote_addr(environ: dict[str, str], remote_addr: str | None) -> str:
  """Return the remote address exactly as Gunicorn should write it to access logs."""
  del environ

  if not remote_addr:
    return "-"

  settings = SETTINGS_BUNDLE.default_settings
  if not settings.anonymize_client_ip_logs:
    return remote_addr

  return _anonymized_access_log_ip(remote_addr)


class GDPRLogger(glogging.Logger):
  """Gunicorn logger that applies cryKeeper's client-IP log privacy rules."""

  def access(self, resp, req, environ, request_time):
    """Override Gunicorn's access log method to skip logging for health checks."""
    remote_addr = environ.get("REMOTE_ADDR")
    request_method = environ.get("REQUEST_METHOD")
    request_path = environ.get("PATH_INFO")

    if (
      remote_addr == "127.0.0.1"
      and request_method == "GET"
      and request_path == "/_crykeeper/healthz"
    ):
      return

    super().access(resp, req, environ, request_time)

  def atoms(self, resp, req, environ, request_time):
    """Override Gunicorn's log atom method to apply IP anonymization to the remote address."""
    atoms = super().atoms(resp, req, environ, request_time)
    atoms["h"] = access_log_remote_addr(environ, atoms.get("h"))
    return atoms


logger_class = GDPRLogger


def child_exit(server, worker):
  del server
  multiprocess.mark_process_dead(worker.pid)
