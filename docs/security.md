# Security Model

[Return to README.md](../README.md)

## Table of Contents

- [Protected Assets](#protected-assets)
- [Trust Boundaries](#trust-boundaries)
- [Application Controls](#application-controls)
- [Operational Controls](#operational-controls)
- [Known Limitations](#known-limitations)
- [Reporting Security Issues](#reporting-security-issues)

## Protected Assets

- User password hashes and TOTP secrets
- Client and contract contact data
- Task structures and time-entry history
- Contract rates and calculated report costs
- Flask signing key and SQLCipher passphrase
- Proprietary Grayhaven branding assets

[Back to top](#security-model)

## Trust Boundaries

The application trusts the deployment system to provide correct secret files,
runtime branding, timezone configuration, TLS termination, proxy forwarding
counts, persistent-storage ownership, and localhost-only health routing.

Authenticated users are trusted to access all client and contract names and
task structures. Administrators are trusted with user management, contact
details, all completed sessions, and contract reports. Clients do not access
the application in this release.

[Back to top](#security-model)

## Application Controls

- Passwords require at least 32 characters with uppercase, lowercase, numeric,
  and special characters and are hashed with Argon2id.
- TOTP is required for the deployment-created administrator and can be enabled
  or disabled by authenticated users after password confirmation.
- Login checks use a dummy Argon2id hash for unknown users and bounded in-memory
  throttles by account and source address.
- Session cookies are HTTP-only and SameSite Lax. Production must enable Secure
  cookies behind TLS.
- State changes use POST requests and CSRF tokens.
- Stable permissions are enforced at route boundaries even though the current
  interface exposes only admin and user behavior.
- SQLCipher encrypts database pages and enables page authentication, memory
  security, secure deletion, foreign keys, and integrity checks.
- Database constraints prevent multiple active timers for one user, invalid
  task/subtask assignments, negative session durations, and removal of the
  last enabled administrator.
- Security headers deny framing, cross-origin resource use, external scripts,
  and browser capabilities not needed by the application.
- Error responses omit internal exception and database details.
- Secret values and SQL parameters are not intentionally logged.

[Back to top](#security-model)

## Operational Controls

- Terminate TLS with the managed production reverse proxy.
- Set `SESSION_COOKIE_SECURE=true` and the exact trusted proxy count.
- Bind the application upstream and health endpoint to loopback only.
- Mount secret files read-only and restrict their host permissions.
- Keep the persistent database directory private to the service account.
- Back up through the verified SQLCipher maintenance command before restic.
- Collect structured logs and alert on health failures and repeated login
  rejection.
- Pin application builds and review dependency and base-image updates before
  deployment.

[Back to top](#security-model)

## Known Limitations

- The login throttle is process-local and designed for the one-worker initial
  deployment. Multi-instance deployments need a shared limiter or proxy-level
  enforcement.
- TOTP recovery codes, email recovery, administrator password reset, and
  administrator TOTP override are not implemented. Authorized operators must
  use a documented offline database procedure when recovery is necessary.
- SQLCipher does not protect data after the running application has unlocked
  it. Host root, container-process compromise, or stolen runtime secrets remain
  critical threats.
- SQLite supports the current low-concurrency workload. Horizontal application
  scaling requires a coordinated database migration.
- Contact and task data are shared with every enabled internal user by design.
- Application logs are structured for future monitoring, but Alloy, Loki,
  fail2ban, dashboards, and alerts are deployment work and are not configured
  by this repository.

[Back to top](#security-model)

## Reporting Security Issues

Use GitHub private vulnerability reporting when the repository is hosted on
GitHub. Do not place exploit details, client information, credentials, or
secret values in a public issue.

[Back to top](#security-model)
