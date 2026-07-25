# Grayhaven Systems LLC Time Tracker

[![CI](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/ci.yml/badge.svg)](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/ci.yml)
[![Unit Tests](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/dean1012/grayhaven-timetracker/actions/workflows/unit-tests.yml)
[![codecov](https://codecov.io/gh/dean1012/grayhaven-timetracker/graph/badge.svg)](https://codecov.io/gh/dean1012/grayhaven-timetracker)

Contract time tracking, billing lifecycle management, and client reporting for
Grayhaven Systems LLC.

This is a real internal tool published for transparency and as an operational
example. The repository contains the application source but excludes
Grayhaven Systems LLC branding, secrets, private data, and
deployment-specific configuration. It is
not a turnkey time-tracking platform. Another organization would need to adapt
the branding, deployment integration, security model, and operating procedures
for its own environment.

## Table of Contents

- [Scope](#scope)
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

## Local Setup

The supplied Docker Compose workflow supports local evaluation on a loopback
listener. Follow [Docker Compose Operations](docs/docker-compose.md) for the
complete preparation, startup, health, backup, restore, update, and key
rotation procedures. See [Configuration](docs/configuration.md) for the
runtime interface and bootstrap-user manifest format.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Documentation

- [Application Architecture](docs/architecture.md): components, permissions,
  time tracking, billing, reporting, and persistence.
- [Configuration](docs/configuration.md): runtime settings, secrets, branding,
  bootstrap users, and proxy integration.
- [Operations](docs/operations.md): managed-host health, lifecycle, database
  maintenance, backup and restore validation, and recovery procedures.
- [Standalone Docker Compose Operations](docs/docker-compose.md): optional
  local startup, backup, restore, and key rotation workflows.
- [Security](docs/security.md): trust boundaries, controls, and deployment
  responsibilities.

[Back to top](#grayhaven-systems-llc-time-tracker)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, validation, and
pull request requirements.

[Back to top](#grayhaven-systems-llc-time-tracker)

## License

Licensed under the [MIT License](LICENSE).

[Back to top](#grayhaven-systems-llc-time-tracker)
