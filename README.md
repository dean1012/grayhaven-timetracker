# Grayhaven Systems LLC Time Tracker

[![CI](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/ci.yml/badge.svg)](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/ci.yml)
[![Unit Tests](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/unit-tests.yml)
[![codecov](https://codecov.io/gh/dean1012/grayhaven-timetracker/graph/badge.svg)](https://codecov.io/gh/dean1012/grayhaven-timetracker)

Contract time tracking, billing lifecycle management, and client reporting for
Grayhaven Systems LLC.

This is a real internal tool published for transparency and as an operational
example. The repository contains the application source but excludes Grayhaven
branding, secrets, private data, and deployment-specific configuration. It is
not a turnkey time-tracking platform. Another organization would need to adapt
the branding, deployment integration, security model, and operating procedures
for its own environment.

## Table of Contents

- [Scope](#scope)
- [Managed Environment](#managed-environment)
- [Local Setup](#local-setup)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Scope

The application provides:

- Role-based administration and user access with TOTP multi-factor
  authentication.
- Clients, contracts, tasks, and optional subtasks.
- One active timer per user, manual time entries, and administrative time
  reassignment.
- Contract archiving and activation with safeguards for active timers.
- A billing lifecycle from pending invoice through invoiced, client paid, and
  disbursed.
- Internal reports and permanent password-protected client report links.
- Append-only audit records and structured JSON application logs.
- An encrypted SQLCipher database with verification, online backup, and key
  rotation utilities.

The application tracks billing state and related metadata. It does not create
or send invoices, process payments, perform payroll, or replace an accounting
system.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Managed Environment

Grayhaven runs this application as a single-instance container behind a managed
TLS reverse proxy. Deployment configuration, host hardening, secret delivery,
monitoring, and scheduled backup orchestration belong in the Grayhaven Ansible
and operations repositories rather than this application repository.

The runtime contract requires:

- Python 3.12 or newer, or the supplied container image.
- A writable persistent data directory.
- private Flask and SQLCipher secret files.
- Runtime branding assets.
- An explicit public origin, trusted hosts, proxy count, and secure cookies for
  an externally reachable deployment.

The supplied Compose definition is intentionally loopback-only and suitable for
local evaluation. It is not a complete managed deployment.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Local Setup

Create the required local directories and secret files:

```bash
mkdir -p data secrets
chmod 700 data secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
  > secrets/flask_secret_key
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
  > secrets/sqlcipher_passphrase
chmod 600 secrets/*
```

Provide a bootstrap-user manifest at `secrets/bootstrap_users`, supply the
required files under `branding/`, then start the application:

```bash
docker compose up --build -d
curl --fail http://127.0.0.1:8000/health
```

Open `http://127.0.0.1:8000`. For the complete runtime interface and bootstrap
manifest format, see [Configuration](docs/configuration.md).

Local defaults must not be reused in a managed deployment. Generate new
secrets and start with a clean database when establishing one.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Documentation

- [Application Architecture](docs/architecture.md): components, permissions,
  time tracking, billing, reporting, and persistence.
- [Configuration](docs/configuration.md): runtime settings, secrets, branding,
  bootstrap users, and proxy integration.
- [Operations](docs/operations.md): health checks, deployment, database
  maintenance, backup and restore validation, and recovery procedures.
- [Security](docs/security.md): trust boundaries, controls, and deployment
  responsibilities.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, validation, and
pull request requirements.

[Back to top](#grayhaven-systems-llc-time-tracker)

## License

Copyright 2026 Grayhaven Systems LLC.

Licensed under the [MIT License](LICENSE).

[Back to top](#grayhaven-systems-llc-time-tracker)
