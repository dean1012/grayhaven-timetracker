# Application Architecture

[Return to README](../README.md)

This document describes the application boundaries and behavior of the
Grayhaven Systems LLC Time Tracker. Host provisioning, reverse-proxy
configuration, secret delivery, and backup scheduling belong to the managed
deployment environment.

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

The application is a server-rendered Flask service for Grayhaven Systems LLC
personnel. It stores operational state in one encrypted SQLCipher database and
is designed to run as a single Gunicorn instance behind a trusted TLS reverse
proxy.

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
- `passkeys.py`: trusted WebAuthn options, session-bound challenge state, and
  registration/authentication verification.
- `bootstrap.py`: validated bootstrap-user provisioning and initial account
  setup.
- `permissions.py`: centralized role and object-state checks.
- `routes.py`: authenticated workflows and shared-report endpoints.
- `reports.py`: report queries and summaries.
- `invoices.py`: invoice preview, issuance, payment, refund, and void
  operations.
- `invoice_routes.py`: administrator invoice workflows and PDF downloads.
- `disbursements.py` and `disbursement_routes.py`: worker balances, account
  transactions, and disbursement history.
- `invoice_time.py`, `invoice_summary.py`, and `invoice_pdf.py`: local-day
  billing calculations, shared snapshot summaries, and invoice rendering.
- `models.py`: SQLAlchemy entities and database constraints.
- `database.py`: SQLCipher connection policy, schema initialization, and
  ordered migrations.
- `audit.py` and `logging_config.py`: audit persistence and structured logging.
- `scripts/database_maintenance.py`: encrypted backup, verification, restore
  support, and key rotation.
- `static/passkeys.mjs`: passkey browser workflows and response conversion.
- `static/report-helpers.mjs`: session cost calculations and refresh edit state.
- `static/app.css`: Time Tracker layout and visual composition.
- `static/app.js`: browser workflows, refresh coordination, and interaction
  behavior.

HTML templates and application CSS are maintained in `templates/` and
`static/`. The canonical Branding component layer is tracked as
`static/shared-components.css` and `static/shared-components.js`; it owns shared
tokens, resets, controls, panels, alerts, tables, hierarchy primitives, and
shared interaction behavior. These files are synchronized byte-for-byte from
the published Branding source before consumer validation. `static/app.css` and
`static/app.js` may add only Time Tracker composition and behavior hooks, not
local forks of shared visuals. Runtime identity assets are supplied separately
through `branding/`.

[Back to top](#application-architecture)

## Identity and Permissions

The application has two roles:

| Capability | User | Administrator |
| --- | --- | --- |
| Create and rename shared tasks and subtasks | Yes | Yes |
| Track and edit or delete own pending time | Yes | Yes |
| View own time and timer state | Yes | Yes |
| Manage clients and contracts | No | Yes |
| Delete shared tasks and subtasks | No | Yes |
| Move another user's pending time | No | Yes |
| Manage invoices and worker disbursements | No | Yes |
| Manage users, TOTP recovery, and passkey wipe-all | No | Yes |
| Create internal and shared reports | No | Yes |
| Review the audit log | No | Yes |

Sessions carry a server-side account version so password resets, role changes,
and account changes can invalidate existing browser sessions. Passwords use
Argon2id. Accounts can enroll TOTP, and configured TOTP is required at login.
Bootstrap provisioning may supply an initial TOTP secret, and administrators
have an assisted recovery path. Sensitive administrator actions require recent
password and TOTP reauthentication or a verified passkey. Passkeys are
optional: password and TOTP sign-in remain permanently available. The ordinary
sign-in and sensitive-action password stages expose explicit passkey buttons,
while conditional login autofill remains a quiet enhancement. Users can name,
add, and remove their own passkeys after reauthentication. Administrators can
see only whether an account has passkeys and can wipe all of them; they cannot
inspect credential details. Bootstrap remains password/TOTP based.

[Back to top](#application-architecture)

## Work Hierarchy

Time is assigned through this hierarchy:

```text
Client
└── Contract
    └── Task
        └── Subtask (optional)
```

A contract owns its billing rate, payment terms, and operational state. The
rate and terms are set at creation and remain fixed. Supported terms are
immediate payment, 7 days, and NET 30. Schema migration assigns NET 30 to
existing contracts that predate payment terms. Archiving a contract stops its
active timers and removes its work from operational selection and reporting.
Activation restores normal availability.

Clients and contracts are archived rather than deleted. Archiving a client
archives its contracts, stops active timers, and rotates its shared-report
password. Restoring a client leaves its contracts archived for separate
activation. Eligible tasks, subtasks, and pending sessions retain soft-delete
controls. Normal queries exclude deleted records; stable identifiers and audit
history remain available for controlled administrative recovery. User accounts
use enablement rather than deletion.

Clients have unique three-digit public numbers. Existing records retain their
previous numeric identifiers, while new clients receive available numbers from
100 through 999. Contract numbers are three-digit sequences within each client.
Application routes, audit display, and invoice numbers use these public
references; database row keys remain internal.

[Back to top](#application-architecture)

## Time Tracking

The database enforces at most one active timer per user. A timer records its
user, task, optional subtask, and start time; the task identifies the contract
and client. Stopping it records its end time. Stored timestamps use UTC and
are displayed in the configured timezone.

Users can create manual entries and edit or delete their own stopped sessions
while those sessions remain pending invoice and belong to an active contract.
They may correct the assignment among visible active contracts and tasks, but
cannot change the owner or invoice metadata. Administrators can also move
pending sessions between users. Corrections and destructive actions are
recorded with reasons and audit context.

Stopped pending sessions are eligible when their stop time falls inside the
selected invoice range. A session that started before the range is included in
full. Exact elapsed time is allocated to each worker's local calendar day.
Each worker-day total is rounded to the nearest quarter hour, with ties rounded
up. Each worker's rounded daily hours are multiplied by the contract rate;
worker amounts are rounded to cents and summed for the invoice total.

Sessions claimed by an invoice are no longer available for ordinary time
corrections. Voiding an unpaid invoice returns them to a correctable state.

[Back to top](#application-architecture)

## Billing Lifecycle

Administrators select a client and active contract, choose a custom range or
the period since the last issued invoice, and review a preview before generating
an invoice. Generation requires sensitive-action authorization and claims the
previewed sessions atomically. Each invoice receives a per-contract sequence
number and stores snapshots of its client, contract, contact, rate, payment
terms, selected sessions, worker-day totals, calculated amount, and PDF.

```text
Pending invoice session → Unpaid invoice → Paid invoice
```

The due date applies the invoice's terms in calendar days and moves forward
past weekends and observed dates for fixed-date United States federal holidays.
Administrators can void an unpaid invoice, returning its sessions to pending
invoice. A paid invoice can be marked refunded without changing the worker's
earned balance. Refunds and voids are permanent and require a correction reason
and sensitive-action authorization.

Invoice PDFs are stored when generated. Downloads overlay the current status
and its transaction ID on the stored PDF so later calculation changes do not
alter issued invoices. Status updates render through the invoice's saved PDF
layout version.

The invoice detail page and PDF present the billing contact, contract rate,
rounded billable work by worker and day, and exact session details. Daily
summaries include empty weekdays within the invoice range as a dash and include
weekends when work was recorded.

Paid invoices add each worker's rounded amount to an independent balance.
Administrators record dated Disbursement, In-Kind Transaction, or Retained
Earnings entries against that balance. In-Kind Transactions and Retained
Earnings are available only to LLC Members. Entries are final once recorded;
workers can view their own transaction history.

[Back to top](#application-architecture)

## Reporting

Administrators can view live client-wide reports. The report query includes
running timers and completed sessions that are still pending invoice under
active contracts. Invoiced, paid, and archived-contract sessions are
intentionally excluded from the operational report.

My Sessions groups pending invoice duration and cost by local calendar day.
Each session's cost is rounded once, then allocated across days so daily costs
sum to the pending total. Running sessions refresh the current day's amount;
crossing midnight refreshes the page to start the next day's row.

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
stores a schema version and applies supported migrations in order. Each
migration runs in an explicit transaction and advances the version marker only
after its schema changes succeed. Re-running initialization at the current
version is idempotent. Unsupported, missing, or newer markers fail closed.

Passkey persistence keeps a random per-user WebAuthn handle, public credential
key and identifier, signature counter, device and backup metadata,
relying-party identity, user-visible name, and timestamps. Ceremony challenges
are expiring, single-use, and bound to the initiating browser session.
Deployment must create and verify a pre-upgrade encrypted backup before
allowing an automatic migration. Application rollback across a schema change
can require restoring that pre-upgrade snapshot.

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
reproduce the Grayhaven Systems LLC managed deployment.

[Back to top](#application-architecture)
