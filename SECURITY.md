# Security Policy

## Supported versions

NetWatch is a personal / portfolio project. Only the latest `main` branch is
maintained and receives fixes.

## Reporting a vulnerability

Please report security issues **privately** using GitHub's
**"Report a vulnerability"** button on the
[Security tab](https://github.com/JackForest84/netwatch/security/advisories/new)
(Private Vulnerability Reporting). Do **not** open a public issue for security
reports.

You can expect an acknowledgement within a few days.

## Deployment notes

- The app binds to `0.0.0.0:8889` **by design** and must run behind a VPN or an
  authenticated reverse proxy — never exposed directly to the internet.
- All secrets (API keys, credentials, session key, TLS key) are loaded from
  files outside the repository (`$NETWATCH_CONFIG_DIR`) or environment variables;
  none are committed. See [`.env.example`](.env.example).
- Authentication uses a signed session cookie (`HttpOnly`, `Secure`,
  `SameSite=Lax`), constant-time password comparison, and a per-IP brute-force
  lockout.

## Dependencies

Dependencies are pinned in [`requirements.txt`](requirements.txt) and monitored
automatically by **Dependabot** + **CodeQL** code scanning. The
`fastapi` / `starlette` / `pydantic` trio is intentionally held together (the app
uses the pydantic v1 API) and upgraded via reviewed pull requests.
