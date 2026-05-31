from ipaddress import ip_address, ip_network

from gunicorn import glogging
from prometheus_client import multiprocess

from app.config import load_settings_bundle

SETTINGS_BUNDLE = load_settings_bundle()


def _anonymized_access_log_ip(value: str) -> str:
  """Reduce logged IP precision while keeping coarse subnet context."""
  try:
    parsed_ip = ip_address(value)
  except ValueError:
    return value

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

  def atoms(self, resp, req, environ, request_time):
    atoms = super().atoms(resp, req, environ, request_time)
    atoms["h"] = access_log_remote_addr(environ, atoms.get("h"))
    return atoms


logger_class = GDPRLogger


def child_exit(server, worker):
  del server
  multiprocess.mark_process_dead(worker.pid)
