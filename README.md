# Grayhaven Systems LLC Time Tracker

[![CI](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/ci.yml/badge.svg)](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/ci.yml)
[![Unit Tests](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/unit-tests.yml)
[![codecov](https://codecov.io/gh/dean1012/grayhaven-timetracker/graph/badge.svg)](https://codecov.io/gh/dean1012/grayhaven-timetracker)

Internal contract time tracking and reporting software for Grayhaven Systems
LLC.

This repository is public for transparency and operational demonstration. It
contains the application source, but it excludes Grayhaven Systems LLC logos,
wordmarks, font files, secrets, and deployment-specific configuration. It is
not a generic turnkey time-tracking product. Another organization would need
to adapt the runtime branding, deployment, and operating procedures.

## Table of Contents

- [Scope](#scope)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Local UAT Deployment](#local-uat-deployment)
- [Runtime Configuration](#runtime-configuration)
- [Reporting](#reporting)
- [Security](#security)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Scope

- Administrator-provisioned accounts with generated temporary credentials,
  hidden admin and user role mappings, and no email dependency.
- Argon2id passwords, TOTP two-factor authentication, self-service profile
  changes, and administrator-assisted password recovery that preserves TOTP.
- Editable client and contract records with an immutable hourly rate per
  contract.
- Shared tasks and one optional layer of subtasks.
- One active timer per user, enforced by the database.
- Manual completed-session entry, correction, and deletion by the owner or an
  administrator, with per-user overlap prevention.
- Administrator-only internal reports and one-click branded PDF reports.
- Live client reports without account registration, protected by a high-entropy
  link and a separately delivered client password. Links can be rotated,
  revoked, and configured with optional expiration.
- Report summaries grouped by task and subtask, including duration, cost, and a
  pie chart.
- Detailed report sessions with user, start time, end time, duration, and cost.
- SQLCipher encryption at rest and UTC timestamp storage.
- An administrator-only, append-only audit log for user, public-report, and
  system activity, with matching structured JSON events for future Loki use.
- Responsive layouts at the documented Grayhaven web breakpoints.

All recorded time is billable. The application intentionally does not include
invoicing, payment processing, estimates, client accounts, or email delivery.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Architecture

The application is a server-rendered Flask service backed by SQLAlchemy and a
single SQLCipher-encrypted SQLite datastore. Gunicorn runs one threaded worker
to keep the deployment suitable for a small host while preserving the
database's single-writer operating model.

The Docker image contains application code and public interface assets.
Grayhaven branding and all secret values are mounted at runtime. See
[Application Architecture](docs/architecture.md) for component and data-flow
details.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Requirements

- Docker Engine or Docker Desktop
- Docker Compose plugin
- Git
- Runtime branding assets listed in
  [Runtime Configuration](#runtime-configuration)

Python 3.13 is used in the container and CI. A local Python environment is only
required for development and direct maintenance-script use.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Local UAT Deployment

Create local runtime directories:

```bash
mkdir -p branding data secrets
chmod 700 data secrets
```

Populate `branding/` from the private Grayhaven branding deployment source.
Create local-only test secrets:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
  > secrets/flask_secret_key
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
  > secrets/sqlcipher_passphrase
python3 -c 'from getpass import getpass; from grayhaven_timetracker.auth import hash_password; print(hash_password(getpass()))' \
  > secrets/initial_admin_password_hash
chmod 600 secrets/*
```

The hash command requires the runtime dependencies to be installed locally.
The cleartext password is read without terminal echo and is not written to a
file.

Build a traceable image and start the local service:

```bash
./scripts/build-image
docker compose up --detach --wait
```

Open <http://127.0.0.1:8000>. The default local administrator email is
`admin@example.invalid`; override it and the display name through environment
variables before starting the Compose project.

Stop the application without deleting its data:

```bash
docker compose down
```

[Back to top](#grayhaven-systems-llc-time-tracker)

## Runtime Configuration

Secret values support either a direct variable or the corresponding
`_FILE` variable. Production automation should use files populated from the
private Grayhaven vault and should not place secrets in the image or repository.

Required settings are:

- `SECRET_KEY` or `SECRET_KEY_FILE`
- `SQLCIPHER_PASSPHRASE` or `SQLCIPHER_PASSPHRASE_FILE`
- at least one enabled administrator supplied through the single-account
  settings or the deployment-managed user manifest described below

The local single-account path uses `INITIAL_ADMIN_EMAIL`,
`INITIAL_ADMIN_FIRST_NAME`, `INITIAL_ADMIN_LAST_NAME`, and
`INITIAL_ADMIN_PASSWORD_HASH` or `INITIAL_ADMIN_PASSWORD_HASH_FILE`.
`INITIAL_ADMIN_TOTP_SECRET` or `INITIAL_ADMIN_TOTP_SECRET_FILE` is optional.
When omitted, the administrator is created without TOTP and can enroll an
authenticator from the profile page after signing in.

Production automation can instead supply `BOOTSTRAP_USERS_FILE` containing a
JSON list rendered from encrypted Grayhaven vault data. This follows the
existing per-domain htpasswd pattern: the vault owns complete credential
entries, Ansible validates and writes a permission-restricted generated file,
and the service reads that file without logging it. The equivalent direct
`BOOTSTRAP_USERS` variable is supported but is not recommended for production.

```json
[
  {
    "email": "administrator@example.invalid",
    "first_name": "Example",
    "last_name": "Administrator",
    "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
    "role": "admin",
    "enabled": true
  },
  {
    "email": "user@example.invalid",
    "first_name": "Example",
    "last_name": "User",
    "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
    "role": "user",
    "enabled": true,
    "totp_secret": "OPTIONALBASE32VALUE"
  }
]
```

Email, first name, last name, password hash, and role are required for each
entry. Role must be `admin` or `user`; `enabled` defaults to `true`; and
`totp_secret` is optional. At least one configured account must be an enabled
administrator. Set `enabled` to `false` to retain history while blocking an
account. Removing an entry stops managing it but does not delete or disable the
database account automatically.

Operational settings include `TZ`, `DATABASE_PATH`, `BRANDING_PATH`,
`CONTACT_URL`, `SESSION_COOKIE_SECURE`, `TRUSTED_PROXY_COUNT`, `TRUSTED_HOSTS`,
and `PUBLIC_BASE_URL`.

`TRUSTED_HOSTS` is a comma-separated browser Host allowlist and defaults to
`localhost,127.0.0.1` for local UAT. Set `PUBLIC_BASE_URL` to the canonical
external HTTPS origin when live report links are generated behind a reverse
proxy. Configuring an external origin requires Secure cookies and a matching
trusted host; the application refuses to start otherwise.

The branding path must contain:

```text
grayhaven-logo-wordmark-dark.svg
grayhaven-logo-wordmark-light.png
favicon.ico
favicon-16.png
favicon-32.png
apple-touch-icon.png
fonts/inter-400.ttf
fonts/inter-500.ttf
fonts/inter-600.ttf
fonts/inter-700.ttf
```

Deployment-managed names, roles, and enabled states are reconciled every
startup. Password and explicitly supplied TOTP values are reapplied only when
their configured fingerprints change, so in-application password recovery and
TOTP enrollment are preserved across ordinary restarts. Omitting TOTP never
removes an authenticator enrolled through the application. Disabling a managed
account stops its active timer, and every reconciled account produces a safe
system audit event.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Reporting

Administrators can open a contract report in a new browser tab or download the
same report as a branded PDF with one click. Both forms snapshot active timers
at report-generation time without stopping or modifying those timers.

An administrator can also create one live report link per contract. A client
does not create an account: they open the opaque link and enter the separately
delivered client report password. Expiration is optional, and administrators
can rotate or revoke the contract link or reset the client password. Password
reset immediately invalidates existing client report browser sessions across
that client's contracts.

The report contains only the client and contract names. Client and contract
contact details remain internal. Currency is USD, timestamps are displayed in
the configured IANA timezone, and stored timestamps remain UTC.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Security

The initial design includes SQLCipher encryption, Argon2id password hashing,
TOTP, CSRF protection, concrete route permissions, secure response headers,
request-size limits, abuse throttling, administrator reauthentication for
credential rotation, session invalidation, trusted-host validation, and
database-level integrity guards. TLS and reverse-proxy access controls remain
deployment boundaries.

See [Security Model](docs/security.md) for assumptions, controls, and known
limitations. See [Operations](docs/operations.md) before backing up, restoring,
or rotating the SQLCipher key.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Documentation

- [Application Architecture](docs/architecture.md)
- [Operations](docs/operations.md)
- [Security Model](docs/security.md)
- [Third-Party Notices](THIRD_PARTY_NOTICES.md)

[Back to top](#grayhaven-systems-llc-time-tracker)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, validation
commands, and contribution guidelines.

[Back to top](#grayhaven-systems-llc-time-tracker)

## License

[MIT](LICENSE)

[Back to top](#grayhaven-systems-llc-time-tracker)
