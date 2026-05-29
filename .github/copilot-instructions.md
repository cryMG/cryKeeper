# Copilot Instructions For cryKeeper

This repository is a minimal Flask-based human cryKeeper that sits in front of nginx via `auth_request`.

## Core architecture

- Keep the cryKeeper stateless. Human verification is represented by an HMAC-signed cookie from `app/cookies.py`; do not introduce server-side session storage unless explicitly requested.
- `app/config.py` loads optional shared `[crykeeper]` defaults plus optional `[[website]]` TOML tables from `CRYKEEPER_CONFIG_FILE`. Non-empty `CRYKEEPER_*` environment variables override only the shared defaults; matching `[[website]]` entries then override most request-scoped settings per host. The Docker image default path is `/app/config.toml`.
- The Docker image runs the Gunicorn process as an unprivileged `cryKeeper` user at runtime. Keep mounted config files readable by that user when you change container deployment guidance.
- The Docker image runs Gunicorn and defaults to 2 workers with 4 threads; keep `CRYKEEPER_GUNICORN_WORKERS` and `CRYKEEPER_GUNICORN_THREADS` documented when you change container runtime behavior, and keep the Valkey guidance aligned with multi-worker deployments.
- The Docker image also initializes Prometheus multiprocess storage for the internal observability endpoints by default via `CRYKEEPER_PROMETHEUS_MULTIPROC_DIR`. Keep that documented whenever container startup or worker behavior changes.
- `rate_limit_valkey_url` remains a shared global setting even when `[[website]]` entries are used. Keep website-specific rate limits separated by keying on host rather than by allowing per-website Valkey URLs.
- `app/routes.py` exposes the main flow under the shared `CRYKEEPER_PATH_PREFIX` prefix and any additional `path_prefix` values from matching `[[website]]` entries. That includes `/clear`, which deletes the verification cookie and redirects back to a safe local path. Keep redirect, form, and static URLs aligned with the effective per-host prefix, and keep `path_prefix` distinct from the reserved internal observability prefix `/_crykeeper`.
- `app/observability.py` exposes internal Prometheus metrics and a server-rendered dashboard under the fixed `/_crykeeper` prefix rather than below `path_prefix`. Keep those endpoints suitable for private reverse-proxy exposure and do not accidentally reclassify them as public challenge routes.
- `app/routes.py` also supports `skip_routes`, `bypass_headers`, `bypass_user_agents`, `bypass_ips`, and `allow_known_search_engines`, which can bypass `/check` before cookie validation. Keep route matching aligned with reverse-proxy forwarding of `X-Original-URI` and `X-Original-Method`, keep `bypass_headers` limited to exact header/value token matches with a minimum token length of 32 characters and deliberate client or proxy handling, and keep IP bypass semantics aligned with trusted proxy handling because `bypass_ips` matches the sanitized client address seen by Flask.
- `app/cookies.py` issues the stateless verification cookie and may bind it to client properties via `CRYKEEPER_HUMAN_COOKIE_BINDING`. Default: `user-agent`; `ip-user-agent` additionally depends on the forwarded client IP. The default `CRYKEEPER_HUMAN_COOKIE_TTL_SECONDS` is 24 hours unless config overrides it.
- `app/__init__.py` applies trusted proxy handling via `CRYKEEPER_TRUSTED_PROXY_HOPS`; when IP binding or HTTPS enforcement changes, keep the proxy assumptions explicit and documented.
- `app/proxy.py` strips forwarded headers unless the direct peer matches `CRYKEEPER_TRUSTED_PROXY_CIDRS`. Keep that aligned with any reverse-proxy deployment guidance.
- `app/security.py` protects return targets against open redirects and redirect loops. Preserve that behavior when changing redirects.
- `app/captcha/` contains the provider-specific server integrations for Cap, hCaptcha, ALTCHA, and dummy mode. Keep provider logic isolated there instead of re-expanding it through `app/routes.py`.
- `app/routes.py` also exposes `/altcha/challenge` below each active `path_prefix` when ALTCHA mode is used for the current host. Keep its secure-transport and rate-limit behavior aligned with the main challenge flow, keep its response format compatible with the current ALTCHA v3 widget bundle rather than the legacy widget-only format, and keep the bundled local ALTCHA asset path aligned with the effective `path_prefix`.
- `app/templates/challenge.html` renders the shared shell while provider-specific form fragments live under `app/templates/providers/`. Keep inline JavaScript out of the template, keep shared browser logic in `app/static/challenge-common.js`, and keep provider-specific browser logic in their own files such as `app/static/challenge-cap.js`, `app/static/challenge-hcaptcha.js`, `app/static/challenge-altcha.js`, and `app/static/challenge-dummy.js`.
- `app/templates/challenge.html` may also render optional `footer_html` from trusted deployment config. It may be a plain string or a locale-keyed TOML table with English fallback. Keep it request-scoped per host, and do not treat it as user input or sanitize away administrator-provided markup.
- `app/routes.py` now owns challenge/verify rate limiting and secure-transport enforcement in addition to the main auth flow. Keep those protections aligned with the challenge UX and translations.
- `app/ratelimit.py` supports both in-memory and Valkey-backed rate limits. Preserve the resilient fallback behavior if you change the backend logic.
- `app/i18n.py` discovers UI translations from the JSON files present under `app/i18n/` at startup and selects them from the request `Accept-Language` header with English fallback. The catalogs are validated at startup, so the default English catalog must keep every UI key used by the challenge page.

## Verification modes

- `CRYKEEPER_VERIFICATION_MODE=dummy` is for wiring tests without a real provider.
- `CRYKEEPER_VERIFICATION_MODE=cap` requires real Cap verification and the configured public Cap URL plus site/secret keys.
- `CRYKEEPER_VERIFICATION_MODE=altcha` uses the ALTCHA widget plus server-side cryptographic verification with the configured HMAC secret.
- `CRYKEEPER_VERIFICATION_MODE=hcaptcha` requires the configured hCaptcha site and secret keys and keeps siteverify validation server-side.
- In Cap and hCaptcha mode, keep verification server-side. Do not trust browser-side success alone.

## Compose model

- `docker-compose.yml` is the checked-in local/testing example stack. It builds the cryKeeper from the current source tree and adds nginx, the demo backend, a bundled local Cap container, and Valkey. It mounts the project-root `config.toml` into the cryKeeper so local file-based configuration is active by default.
- The README installation section should default to the published `ghcr.io/crymg/crykeeper:latest` image; the checked-in `docker-compose.yml` remains the source-based local/testing entry point.
- The example nginx terminates HTTPS with a self-signed certificate on port 8443 and proxies browser-side CAP traffic under `/cap`; generate the cert once on the host with `nginx/demo-cert.cnf` and mount it into the container via `nginx/certs`. Keep `config.toml`, `nginx/nginx.demo.conf`, and `nginx/demo-cert.cnf` aligned with the demo hosts. In the example stack, `localhost` and `cap.localhost` remain Cap demos, `full.localhost` demonstrates a fully protected Dummy host, `dummy.localhost` demonstrates Dummy mode on `/protected/`, `hcaptcha.localhost` demonstrates hCaptcha with public test keys, `altcha.localhost` demonstrates ALTCHA with cryKeeper-hosted challenges, and `dashboard.localhost` exposes only the internal observability dashboard plus metrics. Use `CRYKEEPER_CAP_PUBLIC_BASE_URL=https://localhost:8443/cap` and `CRYKEEPER_CAP_INTERNAL_BASE_URL=http://cap:3000` for the Cap host.
- For local end-to-end testing, always use:

```bash
docker compose up --build
```

- The example nginx config lives in `nginx/nginx.demo.conf` and must preserve the external host and port via forwarded host headers, keep the original protected URL visible while the challenge page is internally proxied with `403 Forbidden`, and still use relative redirects where redirects remain necessary. Keep its fixed `/crykeeper` default host plus the additional demo host prefixes aligned with `config.toml`.

## Important project files

- `Dockerfile`: production image for the cryKeeper only.
- `entrypoint.sh`: container startup wrapper that prepares Prometheus multiprocess storage and then execs Gunicorn or an overridden command.
- `config.example.toml`: example file-based configuration using shared `[crykeeper]` defaults and optional `[[website]]` overrides.
- `examples/demo-backend/app.py`: fake protected upstream used only for local demo/testing. It also exposes `/protected/skip-route/` so the demo can verify `skip_routes` end to end.
- `.env.example`: documented environment template. Keep comments aligned with the real behavior.
- `pyproject.toml`: central Ruff and Bandit configuration for repo-wide Python quality checks.
- `.github/workflows/tests.yml`: CI workflow that runs unit tests plus the configured Python quality checks.
- `.github/workflows/docker-publish.yml`: release automation that publishes the Docker image to GHCR on version tags and as `nightly` on the scheduled build window, but only after a successful `.github/workflows/tests.yml` run for the same commit and while skipping duplicate nightly publishes for the same commit.
- Keep the OCI labels in `Dockerfile` and the OCI manifest annotations in `.github/workflows/docker-publish.yml` aligned so the GitHub Container Registry UI shows package metadata such as the description.
- `README.md`: user-facing setup and operation guide.

## Change discipline

- When behavior, commands, environment variables, architecture, or local testing flow changes, update this file in the same change.
- If you change config keys, config-file precedence, per-website override behavior, or the TOML schema, also update `README.md`, `.env.example`, and `config.example.toml` in the same change.
- If you change the compose structure, also update `README.md` and `.env.example` so all three stay consistent.
- If you add, remove, rename, or change cryKeeper endpoints or their behavior, update the README endpoint list in the same change.
- If you change repo-wide Python quality tooling or formatting rules, keep `pyproject.toml`, `.github/workflows/tests.yml`, and the `README.md` quality-check section aligned.
- If you change Docker image release automation, keep `.github/workflows/docker-publish.yml` and the README section that documents GHCR tag semantics aligned.
- Keep project env vars under the `CRYKEEPER_` prefix. `CRYKEEPER_CAP_INTERNAL_BASE_URL` is optional and should fall back to `CRYKEEPER_CAP_PUBLIC_BASE_URL` when unset. `CRYKEEPER_PATH_PREFIX` configures the shared default cryKeeper route namespace, but the bundled demo keeps its default host fixed on `/crykeeper`; per-website route prefixes are TOML-only and require matching reverse-proxy rules per host.
- If you change cookie binding behavior, keep nginx auth subrequest header forwarding and the user-facing docs aligned, especially for `CRYKEEPER_HUMAN_COOKIE_BINDING=ip-user-agent`.
- If you change trusted proxy handling, keep `CRYKEEPER_TRUSTED_PROXY_HOPS`, nginx forwarded-header sanitization, and the README examples aligned.
- If you change trusted proxy restrictions, keep `CRYKEEPER_TRUSTED_PROXY_CIDRS` guidance aligned with container/demo networking expectations.
- If you change the challenge page scripts or provider asset loading, keep the CSP header, `app/static/challenge-common.js`, the provider-specific scripts, and the template metadata in sync.
- Preserve the minimal-dependency approach unless there is a clear reason to add a new dependency.
- Avoid changes that couple the published Docker image or application runtime to the demo backend or bundled local Cap; the checked-in compose file is local/testing only.
