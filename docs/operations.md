# Operations

[Return to README](../README.md)

This runbook covers application-specific operations. The Grayhaven deployment
repository owns host provisioning, proxy configuration, secret distribution,
image promotion, scheduled backups, and observability integration.

## Table of Contents

- [Service Health](#service-health)
- [Deployment](#deployment)
- [Backups](#backups)
- [Backup and Restore Verification](#backup-and-restore-verification)
- [Database Restore](#database-restore)
- [SQLCipher Key Rotation](#sqlcipher-key-rotation)
- [User Provisioning and Recovery](#user-provisioning-and-recovery)
- [Contract and Billing Corrections](#contract-and-billing-corrections)
- [Shared Client Reports](#shared-client-reports)
- [Timezone Changes](#timezone-changes)
- [Logs and Monitoring](#logs-and-monitoring)

## Service Health

`GET /health` verifies that the keyed database can answer a minimal query. A
healthy service returns HTTP 200 and `{"status":"ok"}`. A database failure
returns HTTP 503 without internal diagnostic details.

The supplied Compose service exposes the application only on
`127.0.0.1:8000`. The managed reverse proxy should keep `/health` private while
allowing local monitoring to query it.

[Back to top](#operations)

## Releases

The project uses GitHub Actions to publish versioned images to GHCR
automatically. To publish a new image:

1. Create a signed tag following the `build/<major>.<minor>.<build>` format
   locally (e.g., `build/0.4.5`).
2. Push the specific tag to GitHub.
3. The `Publish Release Image` workflow automatically triggers, verifies the tag
   signature against the committed release-signing key, and builds the verified
   revision.
4. The workflow pauses at the `container-publish` environment gate. An
   authorized operator must approve the release.
5. Once approved, the image is built and pushed with OCI metadata, an artifact
   attestation, and the immutable digest is logged.

In case of a failure during the automated run, the `Publish Release Image`
workflow supports manual execution via `workflow_dispatch`. Supply the name of
an existing signed build tag (e.g., `build/0.4.5`). Dispatches targeting
branches or unsigned tags will be rejected.

[Back to top](#operations)

## Deployment

Before promoting a release:

1. Confirm CI and unit tests pass for the exact signed revision.
2. Select the published versioned image from GHCR and record its immutable
   digest. Never use `latest`.
3. Confirm the target uses a clean database when the release schema is not
   compatible with an earlier deployment.
4. Render new environment-specific secret files and the initial bootstrap-user
   manifest from the approved vault.
5. Verify persistent volume ownership, runtime branding, trusted hosts, public
   origin, proxy count, timezone, and secure-cookie settings.
6. Start the service and check `/health` through the host monitoring path.
7. Verify administrator login and TOTP, a timer cycle, one representative
   report, shared-report access, and an audit entry.

For an external deployment, set an exact HTTPS origin and trust boundary:

```text
PUBLIC_BASE_URL=https://timetracker.example.invalid
SESSION_COOKIE_SECURE=true
TRUSTED_HOSTS=timetracker.example.invalid
TRUSTED_PROXY_COUNT=1
```

Match the proxy count to the actual controlled hops. Preserve the original
Host and expected forwarded address and scheme headers. Configure proxy access
logs to redact `/shared/reports/<token>` paths because the application cannot
control logs written by the proxy.

[Back to top](#operations)

## Backups

Do not have restic copy the live database file directly. WAL activity can make
an uncoordinated file copy inconsistent. First create an encrypted online
artifact with the application utility:

```bash
mkdir -p data/backups
docker compose exec timetracker \
  python scripts/database_maintenance.py backup \
  /app/data/timetracker.sqlite3 \
  /run/secrets/sqlcipher_passphrase \
  /app/data/backups/timetracker-$(date -u +%Y%m%dT%H%M%SZ).sqlite3
```

The command uses SQLite's online backup API, verifies SQLCipher and SQLite
integrity, writes mode `0600`, and refuses to overwrite an existing path. The
artifact includes application data and the audit history.

Backup orchestration should require this command to succeed before restic
captures the artifact. Verify a retained artifact with its matching key:

```bash
docker compose exec timetracker \
  python scripts/database_maintenance.py verify \
  /app/data/backups/<backup-file> \
  /run/secrets/sqlcipher_passphrase
```

Restic repository configuration, schedules, retention, off-host replication,
and alerting remain deployment responsibilities.

[Back to top](#operations)

## Backup and Restore Verification

Verify the complete backup and restore path periodically and after material
changes to the database, backup job, secret paths, or deployment automation:

1. Identify representative existing records, including users, clients,
   contracts, billing metadata, shared-report configuration, and audit events.
2. Run the online backup command and require the restic job to capture that
   exact artifact.
3. Record the restic snapshot ID, artifact checksum, application version,
   schema version, and key version.
4. Restore the artifact from restic into an isolated path; do not use the local
   pre-snapshot copy.
5. Verify the isolated artifact with
   `scripts/database_maintenance.py verify` and the matching key.
6. Start the matching application build against the restored database on an
   isolated recovery target.
7. Verify health, login, TOTP, the identified records, billing metadata,
   shared-report access, and audit history.
8. Perform a controlled write to prove the restored database remains writable,
   then discard that recovery copy rather than returning it to service.
9. Record the result and dispose of recovery artifacts according to the
   applicable data-retention policy.

This validates the application database path through the complete chain:
consistent SQLCipher artifact, restic capture, restic restore, integrity check,
and application recovery.

[Back to top](#operations)

## Database Restore

1. Identify the approved restic snapshot, backup artifact, application build,
   schema version, and SQLCipher key version.
2. Stop the application and prevent automatic restart.
3. Retain the current database and its `-wal` and `-shm` sidecars for controlled
   rollback and investigation.
4. Restore the encrypted artifact into an isolated path and verify it with the
   matching key.
5. Install it as `data/timetracker.sqlite3`, set the runtime owner and mode
   `0600`, and remove stale sidecars.
6. Start the matching application build.
7. Confirm `/health`, administrator login, TOTP, current records, reports,
   shared-report access, audit history, and one controlled write.
8. Record the recovery point, recovery time, validation, and disposition of the
   replaced database.

Never probe a restored database with guessed keys. A wrong-key error does not
identify the correct key.

[Back to top](#operations)

## SQLCipher Key Rotation

Treat key rotation as offline maintenance:

1. Create and verify a current backup.
2. Stop the service with `docker compose stop timetracker`.
3. Install the proposed key as
   `secrets/sqlcipher_passphrase.new` with mode `0600`.
4. Run:

   ```bash
   docker compose run --rm --no-deps timetracker \
     python scripts/database_maintenance.py rekey \
     /app/data/timetracker.sqlite3 \
     /run/secrets/sqlcipher_passphrase \
     /run/secrets/sqlcipher_passphrase.new
   ```

5. Verify the database with the new key.
6. Atomically promote the new secret through the approved deployment process.
7. Start the service and validate health, login, writes, and reports.
8. Retain the pre-rotation backup and old key only for the approved rollback
   window, then dispose of both through the controlled process.

The utility attempts to restore and verify its pre-rotation backup if rekeying
fails. Keep the service stopped until the database and deployed key are known
to match.

[Back to top](#operations)

## User Provisioning and Recovery

`BOOTSTRAP_USERS_FILE` is a first-install interface. The deployment process
renders its JSON from protected configuration and installs it as a restricted
secret. The application reads it only when the user table is empty; it does not
continuously reconcile existing accounts.

After installation, administrators manage accounts in the application. A
password reset generates a strong temporary password, displays it once,
invalidates the user's existing sessions, and requires a replacement at the
next sign-in. Existing TOTP enrollment is retained.

If a user also loses TOTP access, an administrator can disable that enrollment
after password and TOTP reauthentication. Deliver temporary passwords and new
TOTP provisioning information through separate approved channels. The
application has no email recovery flow.

[Back to top](#operations)

## Contract and Billing Corrections

Archiving a contract stops active timers and removes the contract from normal
selection and client reports. Activation restores it. Both actions require an
administrator and recent reauthentication.

Completed time can be edited or moved only while pending invoice. For a
correction after invoicing, client payment, or disbursement, reverse the session
to the required earlier state, make the correction, then advance it through the
billing lifecycle again with accurate metadata. The audit log records each
step.

Before deleting clients, contracts, or work definitions, return affected
finalized sessions to pending invoice and confirm that deletion is the intended
business action. Audit records remain even when eligible operational data is
removed.

[Back to top](#operations)

## Shared Client Reports

Each client receives a permanent report URL at creation. Until an administrator
generates a report password, that URL cannot grant access. The password is
displayed once and cannot be recovered later.

Share the report URL and password through separate approved channels. Rotating
the password invalidates existing shared-report sessions. The report is live:
running time advances in the browser, and changed eligible work appears without
a full page reload. Invoiced, paid, disbursed, and archived-contract time is not
shown.

[Back to top](#operations)

## Timezone Changes

Set `TZ` to an IANA timezone and recreate the container. Timestamps remain
stored in UTC, so this changes display and entry interpretation without
rewriting stored instants. Validate a representative report after a timezone
change.

[Back to top](#operations)

## Logs and Monitoring

The application emits one JSON object per line to standard error. Request,
authentication, shared-report, and state-change events include safe operational
context without passwords, TOTP values, or report tokens. The encrypted
database also contains the append-only audit history available to
administrators.

The managed environment owns collection, retention, dashboards, alerts, and
access controls. When Grayhaven's Grafana stack is enabled, its integration
should consume the existing structured stream rather than require an
application-specific logging mode. Validate log collection and alerts before
the service receives real data.

Monitor persistent-volume growth because the audit history is intentionally not
editable or deletable through the application.

[Back to top](#operations)
