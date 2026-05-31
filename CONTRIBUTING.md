# Contributing to cryKeeper

Thank you for your interest in contributing to cryKeeper! We welcome contributions from the community to help improve the project. Below are some guidelines to help you get started.

## Developer Setup

Python package files:

- [requirements.txt](requirements.txt) contains the runtime dependencies
- [requirements-dev.txt](requirements-dev.txt) extends it with development tools such as Ruff, Bandit, and the Python minifiers used by the hashed static-asset build step

The following developer commands assume a local virtual environment with the dev dependencies installed:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

If you build the Docker image directly during development or release automation, the Dockerfile also accepts optional build arguments for OCI image metadata:

- `VERSION`: image version string. Defaults to `dev`.
- `VCS_REF`: source revision, typically the Git commit SHA.
- `BUILD_DATE`: image creation timestamp, typically in UTC RFC 3339 format.

Example:

```bash
docker build \
  --build-arg VERSION="$(git describe --tags --always 2>/dev/null || echo dev)" \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t crykeeper:latest .
```

## CSS/JS Minification and Hashing

The static CSS/JS assets are minified and hashed for cache busting. This happens automatically during the Docker build, but you can also run the build script locally if you want to inspect the output or test changes to the static files without rebuilding the entire Docker image.

To create the minified assets outside Docker, run:

```bash
python scripts/build_static_assets.py
```

## Local Python Tests

Tests should be added to the [tests/](tests/) directory, following the naming convention `test_*.py`. Each test file should contain one or more test cases that cover the functionality of the code being tested. Use descriptive names for your test functions to clearly indicate what they are testing.

Run all tests:

```bash
python -m unittest discover -s tests -v
```

Run a single test module:

```bash
python -m unittest discover -s tests -p "test_security_hardening.py" -v
```

## Local Ruff and Bandit

Ruff and Bandit are used for linting and security checks, respectively.
Both tools use the shared configuration in [pyproject.toml](pyproject.toml).

Make sure to run these checks before submitting a pull request:

```bash
ruff check .
ruff format .
bandit -c pyproject.toml -r . -q
```

## Repository Layout

For development, these files are the most important entry points:

- [app/config.py](app/config.py): shared config loading, TOML parsing, per-host overrides
- [app/routes.py](app/routes.py): check, challenge, verify, clear, healthz
- [app/cookies.py](app/cookies.py): stateless signed verification cookies
- [app/i18n.py](app/i18n.py): language discovery and translation fallback
- [app/ratelimit.py](app/ratelimit.py): in-memory and Valkey-backed rate limiting
- [config.example.toml](config.example.toml): reference configuration
- [nginx/nginx.demo.conf](nginx/nginx.demo.conf): working nginx auth_request example used by the demo stack

## Gnuicorn Hints

The Gunicorn access-log redaction happens in [gunicorn.conf.py](gunicorn.conf.py), where a custom logger class rewrites the logged remote address based on the shared `anonymize_client_ip_logs` setting.

## Release Process

When you're ready to release a new version of cryKeeper, please follow these steps:

1. Update the [CHANGELOG.md](CHANGELOG.md) file with the changes for the new version. Follow the format used in previous entries, and make sure to include a section for the new version (exact version string) with a release date.
2. Push your changes to the main branch or create a pull request to merge your changes into the main branch.
3. Check that all tests running on CI are passing.
4. Create a new Git tag for the release using the version string you used in the CHANGELOG.md. For example: `v1.2.3` for releases or `v1.2.3-beta.0` for pre-releases.
5. Push the Git tag to the remote repository.

After the tag is pushed, GitHub Actions will automatically build and publish the new release based on the tag. You can verify that the release has been published by checking the "Releases" section of the GitHub repository.

## GitHub Container Registry

GitHub Actions publishes container images to `ghcr.io/crymg/crykeeper`.
The publish workflow writes the package description, source URL, and license both as OCI labels in the image and as OCI manifest annotations so the GitHub package UI can display them reliably.
Published tags are multi-architecture manifests for `linux/amd64` and `linux/arm64`.

- A Git tag in the form `vX.Y.Z` publishes the tags `vX.Y.Z`, `vX.Y`, `vX`, and `latest`, then creates the matching GitHub release from the corresponding `CHANGELOG.md` section.
- A prerelease tag in the form `vX.Y.Z-suffix` publishes only the exact tag, creates a GitHub prerelease from the matching `CHANGELOG.md` section, and never updates `latest`.
- A tagged release only proceeds when the workflow in [.github/workflows/tests.yml](.github/workflows/tests.yml) has a successful run for the same commit.
- Before a tagged release build starts, `CHANGELOG.md` must contain a non-empty section whose heading starts with `## [<tag>]`, for example `## [v1.2.3] - 2026-05-28`.
- A nightly build publishes the `nightly` tag once per day at 01:00 UTC from the current default-branch commit, as long as that commit does not already carry a version tag, the tests workflow succeeded for that commit, and `nightly` is not already pointing at an image built from that same commit.
- The same nightly publication can also be started manually via the GitHub Actions `workflow_dispatch` trigger for the selected ref.

## AI usage

AI tools can be used to assist with code generation, refactoring, and documentation. However, please ensure that any AI-generated code is reviewed and tested thoroughly before being included in the project.

Always provide proper attribution if you use AI-generated content in your contributions.
State clearly in the pull request description which parts were generated by AI tools. This helps maintain transparency and allows reviewers to focus on the AI-generated sections for careful review.
