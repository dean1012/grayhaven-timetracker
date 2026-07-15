# Application Architecture

[Return to README.md](../README.md)

## Table of Contents

- [Runtime Components](#runtime-components)
- [Request and Data Flow](#request-and-data-flow)
- [Authorization Model](#authorization-model)
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
application emits an access event for each non-health request and additional
audit events for authentication and material state changes.

[Back to top](#application-architecture)

## Authorization Model

The interface exposes only administrator promotion and demotion. Internally,
roles map to stable permission identifiers such as `report:generate`,
`client:add`, and `time_entry:edit_own`.

Administrators manage users, clients, contracts, reports, and all sessions.
Users can view shared client and contract structures, manage tasks and
subtasks, control their own timer, and correct their own completed sessions.
All users can access all current clients and contracts.

Database guards preserve at least one enabled administrator, prevent a subtask
from being assigned to an unrelated task, and enforce one active timer per
user.

[Back to top](#application-architecture)

## Time and Cost Model

Timestamps are stored as naive UTC values and converted through the configured
IANA timezone at the presentation boundary. Ambiguous and nonexistent local
times are rejected when sessions are corrected.

Duration is measured to the second. Cost uses integer contract-rate cents and
decimal arithmetic. Per-session cent allocation is reconciled to each grouped
summary so detailed and summary totals remain equal.

An active timer is represented by a null stop timestamp. Reports substitute
their generation timestamp for display and calculations without changing the
stored timer.

[Back to top](#application-architecture)

## Persistence and Growth

SQLCipher SQLite is appropriate for the initial single-host, low-write
workload. The domain model and SQLAlchemy boundary keep future migration to a
server RDBMS feasible, but such a migration will require schema migrations,
provider-specific integrity constraints, concurrency testing, and revised
backup procedures.

The encrypted database must reside on persistent storage. Branding and secret
mounts are separately managed and are not part of the application image.

[Back to top](#application-architecture)
