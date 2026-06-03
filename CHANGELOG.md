# cryKeeper Changelog

<!--
All notable changes to this project have to be documented in this file.
Each version should have it's own section, and the sections have to be ordered
by release date in descending order.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
Released versions should use the Git tag as the section title, for example
`## [v1.2.3] - 2026-05-28`.
-->

## [Unreleased]

## [v0.2.0] - 2026-06-03

### Added

- Internal health check endpoint at `/_crykeeper/healthz` for container and proxy health checks.
- Health check for the Docker image that uses the new endpoint.
- Support for wildcard website domains like `*.example.com` in the configuration, which match all subdomains of `example.com` and are aggregated under a stable `+.example.com` host bucket in metrics and rate-limit keying. Wildcards do not match the apex domain itself (for example `*.example.com` does not match `example.com`).
- New metrics shown in the dashboard: Checks allowed, Checks challenge required, Rendered challenges

### Changed

- Don't anonymize loopback addresses in the Gunicorn configuration, since they don't represent real clients.
- Don't log health check requests from 127.0.0.1 to reduce noise in the logs.
- Unknown website domains will now be normalized to the `default` host with shared rate limits and metrics, instead of being measured separately. This prevents DoS attacks from creating many unique host entries and consuming resources.

### Fixed

- Some style fixes in the dashboard.
- Only show User-Agent issues in dashboard, if no request had a valid User-Agent per host.

## [v0.1.0] - 2026-05-31

> [!IMPORTANT]
> This is the first release of cryKeeper. 🎉  
> It is **not** recommended for production use yet, but it is ready for testing and feedback.

- First Release with core features
- See the [README](README.md) and [config.example.toml](config.example.toml) for more details on configuration and usage
