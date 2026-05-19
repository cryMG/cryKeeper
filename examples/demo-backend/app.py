from flask import Flask, request

app = Flask(__name__)
SKIP_ROUTE_TEST_PATH = "/protected/skip-route/"


def _normalized_host() -> str:
  """Return the current request host without any port suffix."""
  host = (request.host or "").strip().lower()
  if host.startswith("["):
    return host.split("]", 1)[0].lstrip("[")
  return host.split(":", 1)[0]


def _request_port() -> str:
  """Extract the externally visible port from the current request host."""
  host = (request.host or "").strip()
  if host.startswith("[") and "]:" in host:
    return host.rsplit(":", 1)[1]
  if host.count(":") == 1:
    return host.rsplit(":", 1)[1]
  return "8080"


def _external_scheme() -> str:
  """Prefer the proxy-forwarded scheme so demo links stay on HTTPS behind nginx."""
  forwarded_proto = (request.headers.get("X-Forwarded-Proto") or "").strip().lower()
  if forwarded_proto in {"http", "https"}:
    return forwarded_proto
  return request.scheme or "http"


def _current_host_url(path: str) -> str:
  """Build an absolute URL on the current demo host for one local path."""
  return f"{_external_scheme()}://{request.host}{path}"


def _site_links() -> list[tuple[str, str]]:
  """Return quick links to the protected pages of all demo hosts."""
  scheme = _external_scheme()
  port = _request_port()
  return [
    ("Default Cap demo protected page", f"{scheme}://localhost:{port}/protected/"),
    ("Cap demo protected page", f"{scheme}://cap.localhost:{port}/protected/"),
    ("Fully protected Dummy demo", f"{scheme}://full.localhost:{port}/"),
    ("Dummy demo protected page", f"{scheme}://dummy.localhost:{port}/protected/"),
    (
      "hCaptcha demo protected page",
      f"{scheme}://hcaptcha.localhost:{port}/protected/",
    ),
    ("ALTCHA demo protected page", f"{scheme}://altcha.localhost:{port}/protected/"),
  ]


def _path_prefix_for_host() -> str:
  """Return the gatekeeper path prefix configured for the current demo host."""
  host = _normalized_host()
  prefixes = {
    "cap.localhost": "/cap-check",
    "full.localhost": "/full-check",
    "dummy.localhost": "/dummy-check",
    "hcaptcha.localhost": "/hcaptcha-check",
    "altcha.localhost": "/altcha-check",
  }
  return prefixes.get(host, "/gatekeeper")


def _current_site_links() -> list[tuple[str, str]]:
  """Return quick links for the current demo host, including the skip-routes test."""
  clear_url = _current_host_url(f"{_path_prefix_for_host()}/clear?return=/")
  if _normalized_host() == "full.localhost":
    return [
      ("Open this site's protected root page", _current_host_url("/")),
      (
        "Open this site's protected nested page",
        _current_host_url("/anything/still-protected"),
      ),
      ("Clear verification cookie", clear_url),
    ]
  return [
    ("Open this site's public page", _current_host_url("/")),
    ("Open this site's protected page", _current_host_url("/protected/")),
    ("Open this site's skip_routes test page", _current_host_url(SKIP_ROUTE_TEST_PATH)),
    ("Clear verification cookie", clear_url),
  ]


def _site_content() -> tuple[str, str, str]:
  """Select the headline, description, and accent color for the current demo host."""
  host = _normalized_host()
  if host == "cap.localhost":
    return (
      "Cap demo",
      "This host is protected through /cap-check and uses the same Cap demo setup as the default localhost.",
      "#1d4ed8",
    )
  if host == "dummy.localhost":
    return (
      "Dummy demo",
      "This dedicated demo host is protected through /dummy-check using the built-in Dummy verification mode.",
      "#b45309",
    )
  if host == "full.localhost":
    return (
      "Fully protected Dummy demo",
      "This dedicated demo host uses /full-check with Dummy mode and protects every backend path instead of only /protected/.",
      "#7c3aed",
    )
  if host == "hcaptcha.localhost":
    return (
      "hCaptcha demo",
      "This dedicated demo host is protected through /hcaptcha-check using hCaptcha test keys.",
      "#0f766e",
    )
  if host == "altcha.localhost":
    return (
      "ALTCHA demo",
      "This dedicated demo host is protected through /altcha-check using ALTCHA with gatekeeper-hosted challenges.",
      "#b45309",
    )
  return (
    "Default Cap demo",
    "Use the hostnames below to compare the Cap demos with the fully protected Dummy host and the dedicated Dummy, hCaptcha, and ALTCHA demo hosts.",
    "#1d4ed8",
  )


def _render_page(
  page_title: str,
  page_body: str,
  accent: str,
  requested_path: str,
  extra_html: str = "",
) -> str:
  """Render a small HTML page shared by the demo entrypoint and skip-routes test route."""
  current_site_links = "".join(
    f'<li><a href="{url}">{label}</a></li>' for label, url in _current_site_links()
  )
  links = "".join(
    f'<li><a href="{url}">{label}</a></li>' for label, url in _site_links()
  )
  return f"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{page_title}</title>
  <style>
    body {{
      font-family: Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 40px;
      background: #f5f7fa;
      color: #102a43;
    }}

    article {{
      max-width: 760px;
      margin: 0 auto;
      background: white;
      border-radius: 16px;
      border-top: 10px solid {accent};
      padding: 32px;
      box-shadow: 0 10px 30px rgba(16, 42, 67, 0.12);
    }}

    code {{
      background: #eef2f6;
      padding: 2px 6px;
      border-radius: 6px;
    }}

    a {{
      color: {accent};
    }}

    button {{
      background: {accent};
      border: 0;
      border-radius: 999px;
      color: white;
      cursor: pointer;
      font: inherit;
      padding: 10px 18px;
    }}

    ul {{
      padding-left: 20px;
    }}
  </style>
</head>
<body>
  <article>
    <h1>{page_title}</h1>
    <p>{page_body}</p>
    <p>You reached the demo backend. Depending on the host and path, nginx may require human verification before forwarding here.</p>
    <p>Requested path: <code>{requested_path}</code></p>
    <p>Full URL seen by the backend: <code>{request.url}</code></p>
    <p>Host seen by the backend: <code>{request.host}</code></p>
    {extra_html}
    <p>Quick links for the current site:</p>
    <ul>{current_site_links}</ul>
    <p>Try the demo websites:</p>
    <ul>{links}</ul>
  </article>
</body>
</html>
"""


@app.route(SKIP_ROUTE_TEST_PATH, methods=["GET", "POST"])
def skip_route_demo() -> str:
  """Return a dedicated page that should be reachable through demo skip_routes rules."""
  site_title, _, accent = _site_content()
  extra_html = f"""
    <p>This endpoint is intended for testing <code>skip_routes</code> in the demo stack.</p>
    <p>Request method seen by the backend: <code>{request.method}</code></p>
    <p>If you can open this page directly without solving a challenge, the configured skip rule matched.</p>
    <form method=\"post\" action=\"{_current_host_url(SKIP_ROUTE_TEST_PATH)}\">
      <button type=\"submit\">Repeat this test with POST</button>
    </form>
    """
  return _render_page(
    f"{site_title} skip_routes test",
    f"This page lives under <code>{SKIP_ROUTE_TEST_PATH}</code> and is meant to bypass auth in the demo config.",
    accent,
    request.path,
    extra_html,
  )


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path: str) -> str:
  """Return a tiny HTML page so local nginx tests have a visible protected upstream."""
  requested_path = f"/{path}" if path else "/"
  page_title, page_body, accent = _site_content()
  return _render_page(page_title, page_body, accent, requested_path)
