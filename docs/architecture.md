# Application Architecture

[Return to README.md](../README.md)

## Table of Contents

- [Runtime Components](#runtime-components)
- [Request and Data Flow](#request-and-data-flow)
- [Authorization Model](#authorization-model)
- [Live Report Access](#live-report-access)
- [Audit Event Model](#audit-event-model)
- [Time and Cost Model](#time-and-cost-model)
- [Persistence and Growth](#persistence-and-growth)

## Runtime Components

- Nginx terminates TLS and proxies application requests in production.
- Gunicorn runs one `gthread` worker with four threads.
- Flask renders HTML, handles authenticated workflows, and generates PDFs.
- SQLAlchemy manages domain models and transaction boundaries.
- SQLCipher stores all application and authentication data in one encrypted
  SQLite file.
- Runtime-mounted assets supply Grayhaven logos, favicons, and Inter fonts.
- Standard output and error carry structured JSON logs for container
  collection.

The application image has one non-root process and no separate database
service. The low-resource model is intentional for initial deployment.

[Back to top](#application-architecture)

## Request and Data Flow

The reverse proxy sends an HTTPS request to Gunicorn. Flask opens a
request-scoped database session, loads and validates the authenticated user,
checks the route's concrete permission, executes the transaction, renders the
response, and closes the database session.

State-changing browser requests use POST and Flask-WTF CSRF protection. The
application emits structured access events for each non-health request. It
also persists authenticated and security-relevant public requests plus
semantic authentication and state-change events in the encrypted audit table.

Sign-in validates email and password before deciding whether a second factor is
needed. Accounts with TOTP enabled receive a separate five-minute authenticator
challenge bound to the user ID and current session version. Only successful
completion promotes that pending state into an authenticated application
session. Accepted TOTP counters are atomically recorded and cannot be replayed.
Restarting the password stage does not clear prior TOTP failures. Accounts
without TOTP proceed directly after password validation. Authenticated and
client-report sessions have a fixed 12-hour lifetime that is not extended by
ordinary requests or live-report synchronization.

[Back to top](#application-architecture)

## Authorization Model

The interface exposes only administrator promotion and demotion. Internally,
roles map to stable permission identifiers such as `report:generate`,
`audit:view`, `client:add`, and `time_entry:edit_own`.

Administrators manage users, clients, contracts, reports, and all sessions.
Users can view shared client and contract structures, manage tasks and
subtasks, control their own timer, and correct their own completed sessions.
All users can access all current clients and contracts, including their hourly
rates.

Database guards preserve at least one enabled administrator, prevent a subtask
from being assigned to an unrelated task, prevent overlapping time intervals
for one user, enforce one active timer per user, and reject audit-event updates
or deletion.

[Back to top](#application-architecture)

## Live Report Access

Each client stores one SHA-256 hash of a high-entropy report-link token and an
optional UTC expiration. The token itself is shown only when the link is
created or rotated. Each client has one Argon2id report-password hash and a
monotonically increasing password version. The linked report contains every
contract for that client, newest first, with contract-specific rates and
totals.

A client follows the client link and enters the separately delivered report
password. Successful verification stores only the client identifier, password
version, and authentication timestamp in the signed browser session. Password
reset increments the version, invalidating every existing client report
session. Link rotation, revocation, expiration, and absolute session age are
checked independently for each live synchronization request.

The administrator and client HTML reports use the same server-rendered report
fragment. JavaScript advances active sessions and exactly reconciled group and
overall billing totals once per second. Every three seconds a same-origin
conditional request checks a structural report fingerprint. An unchanged
report returns HTTP 304 without markup or an audit-table write. Timer starts,
stops, edits, deletions, and report-label or rate changes return replacement
markup that is installed without reloading the page. Access loss freezes the
display and marks the report ended.

Shared reports exclude client and contract contact details. The application
redacts report tokens from access, exception, and persistent audit paths.

[Back to top](#application-architecture)

## Audit Event Model

The audit table is append-only at the database layer. Each event records its
UTC timestamp, stable event name, source classification, actor snapshot,
request context, response status when available, and bounded structured
details. User-controlled controls and credential-like detail fields are
removed before persistence or structured log emission.

Administrators can filter the read-only view by source, action, and actor.
Every canonical event is also emitted through the
`grayhaven_timetracker.audit` JSON logger, preserving the fields required for a
later Alloy or Loki pipeline without making Loki part of the application
transaction path.

[Back to top](#application-architecture)

## Time and Cost Model

Timestamps are stored as naive UTC values and converted through the configured
IANA timezone at the presentation boundary. Ambiguous and nonexistent local
times are rejected when sessions are corrected.

Duration is measured to the second. Cost uses integer contract-rate cents and
decimal arithmetic. Per-session cent allocation is reconciled to each grouped
summary so detailed and summary totals remain equal.

An active timer is represented by a null stop timestamp. HTML reports start
from an authoritative server snapshot and advance from browser receipt time,
so a client clock mismatch cannot distort elapsed time. Background
synchronization remains authoritative for timer state. PDF reports substitute
their generation timestamp for display and calculations without changing the
stored timer.

[Back to top](#application-architecture)

## Persistence and Growth

SQLCipher SQLite is appropriate for the initial single-host, low-write
workload. Schema version 4 includes account recovery state, client-wide live
report access,
and the audit trail. The domain model and SQLAlchemy boundary keep future
migration to a server RDBMS feasible, but such a migration will require schema
migrations, provider-specific integrity constraints, concurrency testing, and
revised backup procedures.

The encrypted database must reside on persistent storage. Branding and secret
mounts are separately managed and are not part of the application image. Audit
events intentionally accumulate with application activity, so capacity
monitoring and backup sizing must include that growth.

[Back to top](#application-architecture)
