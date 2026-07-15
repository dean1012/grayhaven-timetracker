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

- Administrator-provisioned accounts with hidden admin and user role mappings.
- Argon2id passwords, TOTP two-factor authentication, and self-service profile
  changes.
- Client and contract records with an immutable hourly rate per contract.
- Shared tasks and one optional layer of subtasks.
- One active timer per user, enforced by the database.
- Completed-session correction and deletion by the owner or an administrator.
- Administrator-only live and one-click PDF contract reports.
- Report summaries grouped by task and subtask, including duration, cost, and a
  pie chart.
- Detailed report sessions with user, start time, end time, duration, and cost.
- SQLCipher encryption at rest and UTC timestamp storage.
- Structured application, access, authentication, and audit logs.
- Responsive layouts at the documented Grayhaven web breakpoints.

All recorded time is billable. The application intentionally does not include
invoicing, payment processing, estimates, client portals, or public reports.

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
python3 -c 'import pyotp; print(pyotp.random_base32())' \
  > secrets/initial_admin_totp_secret
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
- `INITIAL_ADMIN_EMAIL`, `INITIAL_ADMIN_FIRST_NAME`, and
  `INITIAL_ADMIN_LAST_NAME`
- `INITIAL_ADMIN_PASSWORD_HASH` or `INITIAL_ADMIN_PASSWORD_HASH_FILE`
- `INITIAL_ADMIN_TOTP_SECRET` or `INITIAL_ADMIN_TOTP_SECRET_FILE`

Operational settings include `TZ`, `DATABASE_PATH`, `BRANDING_PATH`,
`CONTACT_URL`, `SESSION_COOKIE_SECURE`, and `TRUSTED_PROXY_COUNT`.

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

When the configured administrator email remains unchanged, bootstrap updates
the display name every startup. It only replaces the password hash or TOTP
secret when the corresponding configured value changes. A new email creates a
new enabled administrator and leaves the existing account untouched.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Reporting

Administrators can open a contract report in a new browser tab or download the
same report as a branded PDF with one click. Both forms snapshot active timers
at report-generation time without stopping or modifying those timers.

The report contains only the client and contract names. Client and contract
contact details remain internal. Currency is USD, timestamps are displayed in
the configured IANA timezone, and stored timestamps remain UTC.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Security

The initial design includes SQLCipher encryption, Argon2id password hashing,
TOTP, CSRF protection, concrete route permissions, secure response headers,
request-size limits, login throttling, session invalidation, and database-level
integrity guards. TLS and host access controls remain deployment boundaries.

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
