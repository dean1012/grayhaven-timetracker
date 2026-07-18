# Application Architecture

[Return to README](../README.md)

This document describes the application boundaries and behavior of the
Grayhaven Time Tracker. Host provisioning, reverse-proxy configuration, secret
delivery, and backup scheduling belong to the managed deployment environment.

## Table of Contents

- [System Context](#system-context)
- [Application Structure](#application-structure)
- [Identity and Permissions](#identity-and-permissions)
- [Work Hierarchy](#work-hierarchy)
- [Time Tracking](#time-tracking)
- [Billing Lifecycle](#billing-lifecycle)
- [Reporting](#reporting)
- [Audit and Logging](#audit-and-logging)
- [Persistence](#persistence)
- [Deployment Boundaries](#deployment-boundaries)

## System Context

The application is a server-rendered Flask service for Grayhaven personnel. It
stores operational state in one encrypted SQLCipher database and is designed to
run as a single Gunicorn instance behind a trusted TLS reverse proxy.

Browser requests pass through the reverse proxy to Gunicorn and Flask. Flask
performs authentication, authorization, validation, and database transactions,
then returns HTML. Shared client reports use separate password-protected links
and expose only the report selected by an administrator.

[Back to top](#application-architecture)

## Application Structure

The primary modules are:

- `grayhaven_timetracker/__init__.py`: application factory, request lifecycle,
  security headers, schema initialization, and health endpoint.
- `config.py`: environment, secret, branding, hostname, proxy, and public-origin
  validation.
- `auth.py`: password, session, TOTP, reauthentication, and rate-limit helpers.
- `permissions.py`: centralized role and object-state checks.
- `routes.py`: authenticated workflows and shared-report endpoints.
- `reports.py`: report queries and summaries.
- `models.py`: SQLAlchemy entities and database constraints.
- `database.py`: SQLCipher connection policy and schema compatibility checks.
- `audit.py` and `logging_config.py`: audit persistence and structured logging.
- `scripts/database_maintenance.py`: encrypted backup, verification, restore
  support, and key rotation.

HTML templates and application CSS are maintained in `templates/` and
`static/`. Runtime identity assets are supplied separately through `branding/`.

[Back to top](#application-architecture)

## Identity and Permissions

The application has two roles:

| Capability | User | Administrator |
| --- | --- | --- |
| Track and edit own pending time | Yes | Yes |
| View own time and timer state | Yes | Yes |
| Manage clients, contracts, tasks, and subtasks | No | Yes |
| Move another user's pending time | No | Yes |
| Advance or reverse billing state | No | Yes |
| Manage users and TOTP recovery | No | Yes |
| Create internal and shared reports | No | Yes |
| Review the audit log | No | Yes |

Sessions carry a server-side account version so password resets, role changes,
and account changes can invalidate existing browser sessions. Passwords use
Argon2id. Accounts can enroll TOTP, and configured TOTP is required at login.
Bootstrap provisioning may supply an initial TOTP secret, and administrators
have an assisted recovery path. Sensitive administrator actions require recent
password and TOTP reauthentication.

[Back to top](#application-architecture)

## Work Hierarchy

Time is assigned through this hierarchy:

```text
Client
└── Contract
    └── Task
        └── Subtask (optional)
```

A contract owns its billing rate and operational state. The rate is fixed after
creation so historical value cannot be silently re-priced. Archiving a contract
stops its active timers and removes its work from operational selection and
reporting. Activation restores normal availability.

Deletion is intentionally constrained. Finalized time must first be returned to
the pending-invoice state. Deleting eligible work records removes associated
operational data while retaining the append-only audit history.

[Back to top](#application-architecture)

## Time Tracking

The database enforces at most one active timer per user. A timer records its
user, client, contract, task, optional subtask, start time, and description.
Stopping it creates a time session using the configured display timezone.

Users can create manual entries and edit or delete their own sessions while
those sessions remain pending invoice. Administrators can move pending sessions
between users and work assignments. Corrections and destructive actions are
recorded with reasons and audit context.

Once a session advances beyond pending invoice, ordinary edits are blocked. An
administrator must reverse its billing state before correcting the underlying
time.

[Back to top](#application-architecture)

## Billing Lifecycle

Each time session moves through an explicit lifecycle:

```text
Pending invoice → Invoiced → Client paid → Disbursed
```

The transitions capture the applicable invoice number, invoice date, client
payment date, disbursement date, and transaction number. Administrators can
reverse a transition when correcting operational mistakes. Reversal clears
metadata that no longer applies to the resulting state.

This lifecycle records the state of external billing work. The application does
not generate or send invoices, transfer money, or synchronize with an
accounting platform.

[Back to top](#application-architecture)

## Reporting

Administrators can view live client-wide reports. The report query includes
running timers and completed sessions that are still pending invoice under
active contracts. Invoiced, paid, disbursed, and archived-contract sessions are
intentionally excluded from the operational report.

A client has a permanent shared-report link protected by a separate password.
The report remains live and reflects current eligible work. Administrators can
rotate its password to invalidate existing shared-report sessions. Shared
reports do not grant access to the authenticated application.

[Back to top](#application-architecture)

## Audit and Logging

Security-sensitive and business-state changes append an audit record containing
the actor, action, target, time, result, and structured details. Audit records
are retained independently from operational objects so deletions do not erase
the history of administrative actions.

The application emits structured JSON logs to standard error. Logs provide
runtime and request diagnostics but deliberately exclude secret values. The
managed environment is responsible for collection, retention, alerting, and
access control.

[Back to top](#application-architecture)

## Persistence

SQLAlchemy maps the domain model to one SQLCipher-encrypted SQLite database.
Connections enforce encryption and defensive SQLite settings. The application
stores a schema version and refuses to open an incompatible database rather
than attempting an implicit migration.

This project does not maintain legacy schema migrations. A deployment that
changes to an incompatible schema starts with a clean database after preserving
any records required by the business through an explicitly reviewed process.

The single-instance design is deliberate. SQLite and the process-local security
controls are not intended for horizontally scaled application workers.

[Back to top](#application-architecture)

## Deployment Boundaries

This repository owns application code, its container definition, and the
runtime interface. The managed environment owns:

- TLS termination and reverse-proxy policy.
- Host and container hardening beyond the supplied image defaults.
- Secret generation, delivery, rotation, and recovery.
- Persistent storage, backup schedules, retention, and restore exercises.
- Log collection, dashboards, metrics, and alerts.
- Image promotion and deployment orchestration.

These boundaries are intentional. Copying this repository alone does not
reproduce Grayhaven's managed deployment.

[Back to top](#application-architecture)
