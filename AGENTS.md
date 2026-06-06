# cryKeeper Project Guidelines

## Project Overview

This is a minimal Flask-based human verification gatekeeper that sits in front of nginx via `auth_request`.

## Environment Setup

**CRITICAL**: For any Python-related commands, you MUST use the virtual environment in the `.venv` directory:

```bash
source .venv/bin/activate
```

## Testing Commands

For local end-to-end testing, always use:

```bash
docker compose up --build
```

For running unit tests with coverage:

```bash
coverage run -m unittest discover -s tests -v
coverage report
```

## Testing Requirements

**CRITICAL**: For all new functions and features, appropriate unit tests must be written.

- Write tests for all new functions and features
- Aim for a minimum code coverage of 90%
- Run tests before committing changes to ensure functionality
- Keep tests aligned with the existing test structure in the `tests/` directory
- When adding new functionality, update or add test cases to verify the behavior

## Core Architecture Principles

### Stateless Design

- Keep the cryKeeper stateless
- Human verification is represented by an HMAC-signed cookie from `app/cookies.py`
- Do NOT introduce server-side session storage unless explicitly requested

### Configuration System

- `app/config.py` loads optional shared `[crykeeper]` defaults plus optional `[[website]]` TOML tables from `CRYKEEPER_CONFIG_FILE`
- Non-empty `CRYKEEPER_*` environment variables override only the shared defaults
- Matching `[[website]]` entries override most request-scoped settings per host
- Keep `anonymize_client_ip_logs` as a shared/global setting (not overridden per website)
- Docker image default config path: `/app/config.toml`

### Docker Image Constraints

- Runs Gunicorn as unprivileged `cryKeeper` user at runtime
- Defaults to 2 workers with 4 threads
- Keep `CRYKEEPER_GUNICORN_WORKERS` and `CRYKEEPER_GUNICORN_THREADS` documented when changing container runtime behavior
- Keep Valkey guidance aligned with multi-worker deployments
- Gunicorn access log format should emit anonymized client-IP (same as application logs) via custom logger in `gunicorn.conf.py`
- Initializes Prometheus multiprocess storage via `CRYKEEPER_PROMETHEUS_MULTIPROC_DIR`
- Keep mounted config files readable by the `cryKeeper` user

### Rate Limiting

- `rate_limit_valkey_url` remains a shared global setting even when `[[website]]` entries are used
- Keep website-specific rate limits separated by keying on host (not per-website Valkey URLs)
- `app/ratelimit.py` supports both in-memory and Valkey-backed rate limits
- Preserve resilient fallback behavior if you change backend logic

### Routing & Paths

- `app/routes.py` exposes main flow under shared `CRYKEEPER_PATH_PREFIX` prefix and any additional `path_prefix` values from matching `[[website]]` entries
- `/clear` deletes verification cookie and redirects back to a safe local path
- Keep redirect, form, and static URLs aligned with effective per-host prefix
- Keep `path_prefix` distinct from reserved internal observability prefix `/_crykeeper`

### Enforcement Modes

- `app/routes.py` supports `enforcement_mode` on effective request settings
- **log_only**: `GET /check` evaluates normal bypass/cookie logic and logs would-challenge decisions, but returns pass-through instead of `401` (doesn't lock out live traffic during rollout validation)
- **challenge_passthrough**: Keep normal challenge flow, but allow failed `POST /verify` attempts to return minimal completion page with distinct signed passthrough cookie (not real human-verification cookie)
- `POST /verify` issues real verification cookie only after real successful verification
- Keep URL fragments browser-only by restoring them client-side from challenge page (not sending to backend)

### Observability

- `app/observability.py` exposes internal Prometheus metrics and server-rendered dashboard under fixed `/_crykeeper` prefix (not below `path_prefix`)
- Includes explicit unsolved challenge attempts based on non-success outcomes
- Includes heuristic runtime warnings for common TLS, proxy, cookie, and auth_request header misconfiguration (missing `Host`, `User-Agent`, `X-Forwarded-For`, `X-Forwarded-Proto`, or `X-Original-*` forwarding)
- Does NOT infer silent browser abandonment or prove end-to-end rollout
- Keep endpoints suitable for private reverse-proxy exposure
- Do NOT accidentally reclassify as public challenge routes

### Bypass Mechanisms

- `app/routes.py` supports `skip_routes`, `bypass_headers`, `bypass_user_agents`, `bypass_ips`, and `allow_known_search_engines`
- These bypass `/check` before cookie validation
- Keep route matching aligned with reverse-proxy forwarding of `X-Original-URI` and `X-Original-Method`
- Keep `bypass_headers` limited to exact header/value token matches (minimum token length: 32 characters) with deliberate client/proxy handling
- Keep IP bypass semantics aligned with trusted proxy handling (`bypass_ips` matches sanitized client address seen by Flask)

### IP Logging & Privacy

- `app/routes.py` emits structured `client_ip` log fields for bypass, log-only, and rate-limit decisions
- Keep `_client_ip_value()` as full sanitized client IP for security logic
- Default `anonymize_client_ip_logs` to enabled
- Log only anonymized `/24` IPv4 or `/48` IPv6 prefixes unless deployment explicitly disables that privacy guard

### Cookie Management

- `app/cookies.py` issues stateless verification cookie
- May bind to client properties via `CRYKEEPER_HUMAN_COOKIE_BINDING`
  - Default: `user-agent`
  - `ip-user-agent`: additionally depends on forwarded client IP
- Persist only HMAC digest of binding in cookie payload (not raw IP or header values)
- Default `CRYKEEPER_HUMAN_COOKIE_TTL_SECONDS`: 24 hours (unless config overrides)
- Keep `secret_key` as current signing key
- Keep `previous_secret_keys` or `CRYKEEPER_PREVIOUS_SECRET_KEYS` as verify-only rotation fallbacks (so old cookies can age out without server-side state)

### Trusted Proxy Handling

- `app/__init__.py` applies trusted proxy handling via `CRYKEEPER_TRUSTED_PROXY_HOPS`
- When IP binding or HTTPS enforcement changes, keep proxy assumptions explicit and documented
- `app/proxy.py` strips forwarded headers unless direct peer matches `CRYKEEPER_TRUSTED_PROXY_CIDRS`
- Keep aligned with reverse-proxy deployment guidance

### Security

- `app/security.py` protects return targets against open redirects and redirect loops
- Preserve this behavior when changing redirects

### CAPTCHA Provider Integration

- `app/captcha/` contains provider-specific server integrations for Cap, hCaptcha, ALTCHA, and dummy mode
- Keep provider logic isolated there (not re-expanded through `app/routes.py`)

### ALTCHA Mode

- `app/routes.py` exposes `/altcha/challenge` below each active `path_prefix` when ALTCHA mode is used for current host
- Keep secure-transport and rate-limit behavior aligned with main challenge flow
- Keep response format compatible with current ALTCHA v3 widget bundle (not legacy widget-only format)
- Keep bundled local ALTCHA asset path aligned with effective `path_prefix`

### Frontend Structure

- `app/templates/challenge.html` renders shared shell
- Provider-specific form fragments live under `app/templates/providers/`
- Keep inline JavaScript out of template
- Keep shared browser logic in `app/static/challenge-common.js`
- Keep provider-specific browser logic in their own files:
  - `app/static/challenge-cap.js`
  - `app/static/challenge-hcaptcha.js`
  - `app/static/challenge-altcha.js`
  - `app/static/challenge-dummy.js`

### Asset Build Pipeline

- Local cryKeeper JS and CSS entry assets are build-minified into content-hashed filenames
- `app/static/asset-manifest.json` tracks these for published Docker image
- Keep Flask rendering resilient when manifest is absent in source checkouts
- Keep local asset URL generation aligned between `app/routes.py`, `app/observability.py`, and build step
- Keep manifest-backed hashed assets on 14-day public cache header
- Leave unhashed source-checkout assets uncached
- Do NOT introduce Node.js toolchain for this pipeline unless explicitly requested

### Footer Configuration

- `app/templates/challenge.html` may render optional `footer_html` from trusted deployment config
- May be plain string or locale-keyed TOML table with English fallback
- When no footer configured: use built-in cryKeeper footer
- When `footer_html` set to `-`: hide challenge footer entirely
- Keep it request-scoped per host
- Do NOT treat as user input or sanitize administrator-provided markup
- `app/templates/dashboard.html` should always render built-in default cryKeeper footer (not configured `footer_html` override)

### Challenge/Verify Protections

- `app/routes.py` owns challenge/verify rate limiting and secure-transport enforcement in addition to main auth flow
- Keep those protections aligned with challenge UX and translations

### Internationalization

- `app/i18n.py` discovers UI translations from JSON files under `app/i18n/` at startup
- Selects from request `Accept-Language` header with English fallback
- Catalogs are validated at startup
- Default English catalog must keep every UI key used by challenge page

## Verification Modes

- `CRYKEEPER_VERIFICATION_MODE=dummy`: For wiring tests without real provider
- `CRYKEEPER_VERIFICATION_MODE=cap`: Requires real Cap verification with configured public Cap URL plus site/secret keys
- `CRYKEEPER_VERIFICATION_MODE=altcha`: Uses ALTCHA widget plus server-side cryptographic verification with configured HMAC secret
- `CRYKEEPER_VERIFICATION_MODE=hcaptcha`: Requires configured hCaptcha site and secret keys, keeps siteverify validation server-side
- In Cap and hCaptcha mode: keep verification server-side (do NOT trust browser-side success alone)

## Docker Compose Model

- `docker-compose.yml` is checked-in local/testing example stack
- Builds cryKeeper from current source tree
- Adds nginx, demo backend, bundled local Cap container, and Valkey
- Mounts project-root `config.toml` into cryKeeper (local file-based configuration active by default)
- README installation section should default to published `ghcr.io/crymg/crykeeper:latest` image
- Checked-in `docker-compose.yml` remains source-based local/testing entry point

### Demo Configuration

- Example nginx terminates HTTPS with self-signed certificate on port 8443
- Proxies browser-side CAP traffic under `/cap`
- Generate cert once on host with `nginx/demo-cert.cnf` and mount into container via `nginx/certs`
- Keep `config.toml`, `nginx/nginx.demo.conf`, and `nginx/demo-cert.cnf` aligned with demo hosts
- Demo hosts:
  - `localhost` and `cap.localhost`: Cap demos
  - `full.localhost`: Fully protected Dummy host
  - `dummy.localhost`: Dummy mode on `/protected/`
  - `hcaptcha.localhost`: hCaptcha with public test keys
  - `altcha.localhost`: ALTCHA with cryKeeper-hosted challenges
  - `dashboard.localhost`: Internal observability dashboard plus metrics only
- Use `CRYKEEPER_CAP_PUBLIC_BASE_URL=https://localhost:8443/cap` and `CRYKEEPER_CAP_INTERNAL_BASE_URL=http://cap:3000` for Cap host
- Example nginx auth_request locations mirror `X-CryKeeper-Token` into `GET /check` for local `bypass_headers` behavior and dev benchmark
- Keep README guidance aligned if you change those forwarded headers

### Nginx Config

- Example nginx config lives in `nginx/nginx.demo.conf`
- Must preserve external host and port via forwarded host headers
- Keep original protected URL visible while challenge page is internally proxied with `403 Forbidden`
- Still use relative redirects where redirects remain necessary
- Keep gzip enabled for compressible demo responses
- Keep fixed `/crykeeper` default host plus additional demo host prefixes aligned with `config.toml`

## Important Project Files

- `Dockerfile`: Production image for cryKeeper only
- `entrypoint.sh`: Container startup wrapper that prepares Prometheus multiprocess storage and execs Gunicorn or overridden command
- `config.example.toml`: Example file-based configuration using shared `[crykeeper]` defaults and optional `[[website]]` overrides
- `examples/demo-backend/app.py`: Fake protected upstream used only for local demo/testing; exposes `/protected/skip-route/` to verify `skip_routes` end to end
- `scripts/benchmark_auth_request.py`: Local dev benchmark comparing nginx responses for direct backend access, challenge fallback, valid cookies, skip routes, and optional forwarded header bypasses against running demo stack
- `.env.example`: Documented environment template; keep comments aligned with real behavior
- `pyproject.toml`: Central Ruff and Bandit configuration for repo-wide Python quality checks
- `.github/workflows/tests.yml`: CI workflow that runs unit tests plus configured Python quality checks
- `.github/workflows/docker-publish.yml`: Release automation that publishes Docker image to GHCR on version tags and as `nightly` on scheduled build window (only after successful `.github/workflows/tests.yml` run for same commit, skipping duplicate nightly publishes for same commit)
- Keep OCI labels in `Dockerfile` and OCI manifest annotations in `.github/workflows/docker-publish.yml` aligned (so GHCR UI shows package metadata like description)
- `README.md`: User-facing setup and operation guide

## Change Discipline

**CRITICAL**: When behavior, commands, environment variables, architecture, or local testing flow changes, update AGENTS.md in the same change.

### Config Changes

- If you change config keys, config-file precedence, per-website override behavior, or TOML schema, also update:
  - `README.md`
  - `.env.example`
  - `config.example.toml`
  (all in the same change)

### Compose Changes

- If you change compose structure, also update:
  - `README.md`
  - `.env.example`
  (so all three stay consistent)

### Endpoint Changes

- If you add, remove, rename, or change cryKeeper endpoints or their behavior, update the README endpoint list in the same change

### Quality Tooling Changes

- If you change repo-wide Python quality tooling or formatting rules, keep aligned:
  - `pyproject.toml`
  - `.github/workflows/tests.yml`
  - `README.md` quality-check section

### Docker Release Changes

- If you change Docker image release automation, keep aligned:
  - `.github/workflows/docker-publish.yml`
  - README section that documents GHCR tag semantics

### Environment Variable Naming

- Keep project env vars under the `CRYKEEPER_` prefix
- `CRYKEEPER_CAP_INTERNAL_BASE_URL` is optional and should fall back to `CRYKEEPER_CAP_PUBLIC_BASE_URL` when unset
- `CRYKEEPER_PATH_PREFIX` configures shared default cryKeeper route namespace
- Bundled demo keeps its default host fixed on `/crykeeper`
- Per-website route prefixes are TOML-only and require matching reverse-proxy rules per host

### Cookie Binding Changes

- If you change cookie binding behavior, keep aligned:
  - nginx auth subrequest header forwarding
  - user-facing docs
  (especially for `CRYKEEPER_HUMAN_COOKIE_BINDING=ip-user-agent`)

### Trusted Proxy Changes

- If you change trusted proxy handling, keep aligned:
  - `CRYKEEPER_TRUSTED_PROXY_HOPS`
  - nginx forwarded-header sanitization
  - README examples

### Trusted Proxy CIDRs

- If you change trusted proxy restrictions, keep `CRYKEEPER_TRUSTED_PROXY_CIDRS` guidance aligned with container/demo networking expectations

### Frontend Changes

- If you change challenge page scripts or provider asset loading, keep in sync:
  - CSP header
  - `app/static/challenge-common.js`
  - provider-specific scripts
  - template metadata

### Dependencies

- Preserve minimal-dependency approach unless there is a clear reason to add a new dependency

### Decoupling

- Avoid changes that couple published Docker image or application runtime to demo backend or bundled local Cap
- Checked-in compose file is local/testing only
