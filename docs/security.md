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
- Permanent live report tokens, report-password hashes, and report browser
  sessions
- Append-only audit history and actor snapshots
- Flask signing key and SQLCipher passphrase
- Proprietary Grayhaven branding assets

[Back to top](#security-model)

## Trust Boundaries

The application trusts the deployment system to provide correct secret files,
runtime branding, timezone configuration, TLS termination, proxy forwarding
counts, persistent-storage ownership, and localhost-only health routing.

Authenticated users are trusted to access all client and contract names,
hourly rates, and task structures. Administrators are trusted with user
management, contact details, all completed sessions, and client reports.
Clients may access an explicitly shared live client report without an account.
That boundary requires both the client's opaque high-entropy link and the
client's administrator-delivered report password. Shared reports exclude
internal contact details.

[Back to top](#security-model)

## Application Controls

- Passwords require at least 32 characters with uppercase, lowercase, numeric,
  and special characters and are hashed with Argon2id.
- Deployment automation can reconcile multiple administrator and standard-user
  accounts from a permission-restricted JSON manifest containing Argon2id
  hashes and optional per-account TOTP seeds. TOTP can be enrolled from the
  profile page when omitted. Standard users created inside the application
  receive a unique TOTP secret. Disabling an active method requires the current
  password and TOTP.
- Login checks use a dummy Argon2id hash for unknown users and bounded in-memory
  throttles by account and source address. TOTP is requested on a separate page
  only after password validation, using a five-minute challenge bound to the
  account's current session version. The same throttles cover rejected TOTP
  codes, restarting the password stage cannot reset TOTP failures, and each
  accepted TOTP counter is atomically recorded for single-use enforcement.
- Administrator-assisted password recovery generates a temporary password,
  invalidates existing sessions, forces a password change, preserves TOTP, and
  sends no email.
- User-password and client-report-password rotation require the acting
  administrator's current password and TOTP and apply a separate abuse limit.
- Session cookies are HTTP-only and SameSite Lax. Authenticated and client
  report sessions have a fixed 12-hour lifetime and are not refreshed by
  ordinary requests. Authentication clears pre-login session state before
  establishing the authenticated session. Production must enable Secure
  cookies behind TLS.
- State changes use POST requests and CSRF tokens.
- Stable permissions are enforced at route boundaries even though the current
  interface exposes only admin and user behavior.
- Browser Host values are checked against an explicit allowlist. External live
  report URLs require a canonical HTTPS origin, Secure cookies, and a matching
  trusted host.
- SQLCipher encrypts database pages and enables page authentication, memory
  security, secure deletion, foreign keys, and integrity checks.
- Database constraints prevent multiple active timers for one user, invalid
  task/subtask assignments, overlapping time for one user, negative session
  durations, removal of the last enabled administrator, and audit history
  updates or deletion.
- Permanent report tokens are stored in the encrypted SQLCipher database so the
  client URL can be displayed and reused. Client report passwords use Argon2id,
  can be replaced independently, and invalidate existing report browser
  sessions by version. Every live synchronization rechecks the token, password
  version, and client-report session age.
- Security headers deny framing, cross-origin resource use, external scripts,
  and browser capabilities not needed by the application.
- Error responses omit internal exception and database details.
- Audit details discard credential-like fields. Shared report tokens and
  Unicode control characters are redacted from application, exception, access,
  and audit log text.

[Back to top](#security-model)

## Operational Controls

- Terminate TLS with the managed production reverse proxy.
- Set `SESSION_COOKIE_SECURE=true` and the exact trusted proxy count.
- Set the exact `TRUSTED_HOSTS` allowlist and canonical `PUBLIC_BASE_URL`.
- Bind the application upstream and health endpoint to loopback only.
- Mount secret files read-only and restrict their host permissions.
- Keep the persistent database directory private to the service account.
- Back up through the verified SQLCipher maintenance command before restic.
- Collect structured logs and alert on health failures and repeated login
  rejection.
- Redact shared report tokens in reverse-proxy access logs and monitor database
  capacity for append-only audit growth.
- Pin application builds and review dependency and base-image updates before
  deployment.
- Run the container with a read-only root filesystem, no Linux capabilities,
  no privilege escalation, a bounded process count, and a constrained
  temporary filesystem.

[Back to top](#security-model)

## Known Limitations

- Login, shared-report, and sensitive-action throttles are process-local and
  designed for the one-worker initial deployment. Multi-instance deployments
  need a shared limiter or proxy-level enforcement.
- TOTP recovery codes, email recovery, and administrator TOTP override are not
  implemented. Password reset deliberately preserves TOTP, so loss of both
  factors requires an authorized offline recovery procedure.
- SQLCipher does not protect data after the running application has unlocked
  it. Host root, container-process compromise, or stolen runtime secrets remain
  critical threats.
- SQLite supports the current low-concurrency workload. Horizontal application
  scaling requires a coordinated database migration.
- Client and contract names, hourly rates, and task data are shared with every
  enabled internal user by design.
- The audit history is append-only and has no in-application retention or
  deletion workflow. Capacity monitoring and a future approved archival policy
  are operational requirements.
- Application and audit logs are structured for future monitoring, but Alloy,
  Loki, fail2ban, dashboards, and alerts are deployment work and are not
  configured by this repository.

[Back to top](#security-model)

## Reporting Security Issues

Use GitHub private vulnerability reporting when the repository is hosted on
GitHub. Do not place exploit details, client information, credentials, or
secret values in a public issue.

[Back to top](#security-model)
