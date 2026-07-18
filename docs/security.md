# Security Model

[Return to README](../README.md)

This document describes the application security model and the controls the
managed deployment must provide. It is not a claim that an unmodified checkout
is suitable for an arbitrary environment.

## Table of Contents

- [Protected Assets](#protected-assets)
- [Trust Boundaries](#trust-boundaries)
- [Application Controls](#application-controls)
- [Operational Controls](#operational-controls)
- [Known Limitations](#known-limitations)
- [Reporting Security Issues](#reporting-security-issues)

## Protected Assets

- Password hashes, TOTP secrets, and authenticated sessions.
- Client, contract, task, rate, time, and billing data.
- Permanent shared-report tokens, password hashes, and report sessions.
- Append-only audit records and structured operational logs.
- Flask signing keys, SQLCipher passphrases, and encrypted backups.
- Proprietary branding supplied outside the public repository and image.

[Back to top](#security-model)

## Trust Boundaries

The application trusts the deployment system to provide correct secrets,
branding, timezone, persistent-storage permissions, TLS termination, trusted
hosts, and proxy-hop configuration. Compromise of the host, service process, or
runtime secrets is outside the protection provided by database encryption.

Enabled internal users can access the client and work structures needed for
time entry. Administrators can manage all users and business records, change
billing state, create shared-report credentials, and inspect the audit log.

A client can access its live report without an application account only by
presenting both the client's high-entropy permanent URL and the separately
delivered report password. Shared-report sessions are isolated from
authenticated application sessions.

[Back to top](#security-model)

## Application Controls

- Passwords use Argon2id and the application enforces its configured length and
  composition policy.
- Enrolled TOTP is required at login. Its separate, time-bounded challenge
  prevents reuse of an accepted counter.
- Unknown-account login performs a dummy password verification to reduce
  account-enumeration timing differences.
- Login, shared-report, and sensitive-action failures use bounded in-process
  throttles.
- Account password resets invalidate existing sessions and force a password
  change. Administrator-assisted TOTP disablement requires recent
  reauthentication.
- Sensitive administrator actions require the administrator's current password
  and a new TOTP code.
- Session cookies are HTTP-only, SameSite Lax, host-only, and fixed-lifetime.
  External deployments must enable Secure cookies.
- State-changing browser requests use POST and CSRF protection.
- Route permissions and object-state checks are centralized and enforced on the
  server.
- Browser Host values use an explicit allowlist. A configured public origin
  must be HTTPS and match that allowlist.
- SQLCipher encrypts database pages and connections enable defensive SQLite
  settings, secure deletion, foreign keys, and integrity checks.
- Database constraints protect timer uniqueness, work assignment integrity,
  session duration, administrator availability, and audit immutability.
- Shared-report passwords use Argon2id. Rotation invalidates previous report
  sessions, and plaintext generated passwords are displayed only through a
  short-lived one-time confirmation.
- Security headers restrict framing, resource origins, browser capabilities,
  and content types.
- Error responses omit internal exception and database details.
- Credential-like fields and shared-report tokens are excluded or redacted from
  application and audit logs.

[Back to top](#security-model)

## Operational Controls

- Terminate TLS at a managed reverse proxy and do not expose Gunicorn directly.
- Set the exact public origin, trusted hosts, proxy-hop count, and Secure-cookie
  policy.
- Keep the application and health listener on a private or loopback interface.
- Generate secrets per environment, mount them read-only, rotate them through a
  controlled process, and restrict host permissions.
- Keep the persistent database and backup artifacts private to the service
  identity.
- Create a verified online SQLCipher artifact before restic captures the
  application database.
- Redact shared-report tokens in reverse-proxy logs.
- Pin release images by immutable digest and review dependency and base-image
  updates.
- Run the container with its read-only root filesystem, dropped capabilities,
  no privilege escalation, bounded process count, and constrained temporary
  filesystem.
- Collect structured logs, monitor persistent capacity, and alert on health and
  repeated authentication failures.

[Back to top](#security-model)

## Known Limitations

- Rate limiters are process-local and designed for the single-worker
  deployment. Multiple instances require a shared limiter or equivalent proxy
  control.
- The application has no email recovery or recovery-code workflow.
  Administrator TOTP recovery depends on another administrator retaining access.
- SQLCipher protects data at rest, not data available to the unlocked running
  process.
- SQLite is appropriate for the intended low-concurrency, single-instance
  workload. Horizontal scaling requires a different persistence design.
- Enabled internal users share client names, contract names, task structures,
  and rates by design.
- The audit history has no in-application deletion or retention workflow.
  Capacity and any approved archival process are operational responsibilities.
- Grafana, log shipping, host intrusion controls, dashboards, and alert rules
  are deployment integrations and are not included in this repository.

[Back to top](#security-model)

## Reporting Security Issues

Use GitHub private vulnerability reporting when the repository is hosted on
GitHub. Do not place exploit details, client information, credentials, or
secret values in a public issue.

[Back to top](#security-model)
