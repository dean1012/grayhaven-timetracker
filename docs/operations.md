# Operations

[Return to README](../README.md)

This runbook covers application-specific work on a Grayhaven managed host.
Host provisioning, proxy configuration, secret distribution, image promotion,
scheduled backups, and observability integration remain owned by the managed
deployment repositories. For optional standalone/local operation, see the
[standalone container guide](docker-compose.md).

## Table of Contents

- [Service Health](#service-health)
- [Releases](#releases)
- [Managed Service Lifecycle](#managed-service-lifecycle)
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

On the managed host, check the systemd unit, the approved running image, and
the loopback endpoint with the configured public hostname:

```bash
sudo systemctl status grayhaven-timetracker.service
sudo podman container inspect \
  --format '{{.ImageName}} {{.ImageDigest}}' \
  grayhaven-timetracker
curl --fail --silent \
  --header 'Host: <configured-hostname>' \
  http://127.0.0.1:8000/health
```

The reverse proxy keeps `/health` private. Replace `<configured-hostname>` with
the environment's Time Tracker hostname; the application rejects untrusted
Host headers.

[Back to top](#operations)

## Releases

The project publishes versioned images to GHCR through GitHub Actions:

1. Create a signed `build/<major>.<minor>.<build>` tag from a clean,
   synchronized `main` revision whose CI and unit tests passed.
2. Push only that tag.
3. Approve the `container-publish` environment gate after the workflow verifies
   the tag signature and tagged revision.
4. Record the immutable published digest and verify that the public image can
   be pulled without authentication.

The workflow supports manual dispatch only for an existing signed build tag.
Branches and unsigned tags are rejected. Never move, replace, reuse, or delete
a published build tag; corrections require a new signed tag and digest.

[Back to top](#operations)

## Managed Service Lifecycle

The container lifecycle is owned by
`grayhaven-timetracker.service`. Use systemd for maintenance:

```bash
sudo systemctl stop grayhaven-timetracker.service
sudo systemctl is-active grayhaven-timetracker.service
sudo systemctl start grayhaven-timetracker.service
```

Require `systemctl is-active` to report `inactive` before changing database or
key files. Direct `podman stop` or `podman start` is unsupported: systemd treats
a direct container stop as an unexpected exit and recreates the container.
One-off `podman run` and `podman exec` maintenance commands documented below do
not replace systemd lifecycle control.

[Back to top](#operations)

## Backups

Create the managed application and host backup with:

```bash
sudo grayhaven-backupctl backup
```

This command invokes the authoritative managed backup script. On a Time Tracker
host, that script first requires the systemd service to be active, creates an
encrypted online database snapshot through SQLite's backup API, verifies both
SQLCipher and SQLite integrity, and atomically publishes the verified artifact
under `/var/lib/grayhaven/timetracker/backups`. Only then does restic capture
that directory through the configured local and remote backup workflow. The
live database and its WAL and SHM sidecars are deliberately excluded from
restic.

Do not substitute a direct restic invocation or copy the live database. Record
the generated artifact name, checksum, restic snapshot ID, application image
digest, schema version, and SQLCipher key version as one recovery point.

Verify a retained local artifact with the running approved container and its
deployed key:

```bash
sudo podman exec grayhaven-timetracker \
  python scripts/database_maintenance.py verify \
  /app/backups/<backup> \
  /run/secrets/sqlcipher_passphrase
```

[Back to top](#operations)

## Backup and Restore Verification

Verify the complete recovery path periodically and after material changes to
the schema, image, backup hook, key, or managed backup configuration:

1. Identify representative users, clients, contracts, billing metadata,
   shared-report configuration, and audit events.
2. Run `sudo grayhaven-backupctl backup` and require it to succeed.
3. Use `sudo grayhaven-backupctl list` and
   `sudo grayhaven-backupctl ls <snapshot> --path
   /var/lib/grayhaven/timetracker/backups --recursive` to confirm that the
   recorded verified artifact is present in the expected snapshot.
4. Restore that artifact to an isolated target. Do not validate only the local
   pre-restic copy.
5. Verify the isolated artifact with the exact approved image digest, matching
   schema, and matching SQLCipher key.
6. Start that matching image against a disposable copy on an isolated recovery
   target. Verify health, login, TOTP, the selected records, billing metadata,
   reports, shared-report access, audit history, and a controlled write.
7. Record the result and dispose of recovery copies under the applicable
   retention policy.

Keep the current production database and key untouched during an isolated
exercise. A backup is not accepted merely because restic listed or restored a
file; the encrypted artifact and recovered application data must both pass
validation.

[Back to top](#operations)

## Database Restore

Select the recovery point before changing the host. Record the application
image digest, schema version, SQLCipher key version, restic snapshot, and Time
Tracker artifact name. Never probe an artifact with guessed keys.

If the approved artifact is already local, verify it while the service is
running:

```bash
sudo podman exec grayhaven-timetracker \
  python scripts/database_maintenance.py verify \
  /app/backups/<backup> \
  /run/secrets/sqlcipher_passphrase
```

If it is not local, restore the backups directory beneath an isolated target:

```bash
sudo grayhaven-backupctl restore latest \
  --target /tmp \
  --path /var/lib/grayhaven/timetracker/backups
```

`latest` selects the newest matching recovery point. Modify the selector or
command when the approved artifact belongs to a specific snapshot or point in
time; do not assume that the newest snapshot is always correct. See
[Restoring to a Target Directory](https://github.com/dean1012/grayhaven-backupctl/blob/main/docs/operations.md#restoring-to-a-target-directory)
for the authoritative selector, target-tree, overwrite, and snapshot behavior.

Verify a remotely restored artifact before installing it. Use the approved
immutable image and the deployed matching key without starting the managed
service:

```bash
sudo podman run --rm \
  --user 777:777 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop all \
  --security-opt no-new-privileges \
  --volume /tmp/var/lib/grayhaven/timetracker/backups/<backup>:/recovery/timetracker.sqlite3:ro,Z \
  --volume /var/lib/grayhaven/timetracker/secrets:/run/secrets:ro,Z \
  <approved-image>@sha256:<digest> \
  python scripts/database_maintenance.py verify \
  /recovery/timetracker.sqlite3 \
  /run/secrets/sqlcipher_passphrase
```

After verification, stop the systemd-owned service and enforce the inactive
state before touching database files:

```bash
sudo systemctl stop grayhaven-timetracker.service
if sudo systemctl is-active --quiet grayhaven-timetracker.service; then
  echo 'grayhaven-timetracker.service is still active' >&2
  exit 1
fi
```

Preserve the complete live database generation in a root-only rollback
directory, including any WAL and SHM sidecars, then remove the live generation:

```bash
rollback_dir="$(sudo mktemp -d \
  /var/lib/grayhaven/timetracker/rollback.XXXXXXXX)"
for path in \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3 \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3-wal \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3-shm; do
  if sudo test -e "$path"; then
    sudo cp -a -- "$path" "$rollback_dir/"
  fi
done
printf 'Rollback directory: %s\n' "$rollback_dir"
sudo rm -f -- \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3 \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3-wal \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3-shm
```

For an already-present local application backup, install it with:

```bash
sudo cp -a \
  /var/lib/grayhaven/timetracker/backups/<backup> \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
```

For an artifact restored beneath `/tmp`, install it with:

```bash
sudo cp -a \
  /tmp/var/lib/grayhaven/timetracker/backups/<backup> \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
```

Restore the managed owner, mode, and SELinux context:

```bash
sudo chown 777:777 \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
sudo chmod 0600 \
  /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
sudo restorecon -RF \
  /var/lib/grayhaven/timetracker/data \
  /var/lib/grayhaven/timetracker/backups
```

Start only through systemd and validate the restored service:

```bash
sudo systemctl start grayhaven-timetracker.service
sudo systemctl is-active --quiet grayhaven-timetracker.service
curl --fail --silent \
  --header 'Host: <configured-hostname>' \
  http://127.0.0.1:8000/health
sudo podman container inspect \
  --format '{{.ImageName}} {{.ImageDigest}}' \
  grayhaven-timetracker
```

Then verify administrator login, TOTP, current records, billing metadata,
reports, shared-report access, audit history, and one controlled write. Retain
the rollback directory and matching prior key until recovery is accepted. If
validation fails, stop the service again, remove the failed database and
sidecars, restore the complete prior generation from the recorded rollback
directory, restore owner/mode/SELinux context, and start through systemd.

[Back to top](#operations)

## SQLCipher Key Rotation

Treat key rotation as offline maintenance and coordinate it with the approved
secret source:

1. Run `sudo grayhaven-backupctl backup`, verify the new artifact, and record
   the current image digest, schema, and key version.
2. Install the proposed key as
   `/var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase.new`, owned by
   UID/GID 777 with mode `0400`, through the approved secret-delivery process.
3. Record the currently running immutable image, stop
   `grayhaven-timetracker.service`, and require it to be inactive.
4. Preserve the database, sidecars, and current key in a root-only rollback
   directory.
5. Run the rekey utility with the same approved immutable image:

   ```bash
   sudo podman run --rm \
     --user 777:777 \
     --read-only \
     --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
     --cap-drop all \
     --security-opt no-new-privileges \
     --volume /var/lib/grayhaven/timetracker/data:/app/data:Z \
     --volume /var/lib/grayhaven/timetracker/secrets:/run/secrets:ro,Z \
     <approved-image>@sha256:<digest> \
     python scripts/database_maintenance.py rekey \
     /app/data/timetracker.sqlite3 \
     /run/secrets/sqlcipher_passphrase \
     /run/secrets/sqlcipher_passphrase.new
   ```

6. Verify the database with the proposed key using the same one-off container
   shape and `scripts/database_maintenance.py verify`.
7. Atomically replace the deployed key, restore its managed metadata and
   SELinux context, and update the approved encrypted configuration to the same
   value before the next convergence:

   ```bash
   sudo mv -f -- \
     /var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase.new \
     /var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase
   sudo chown 777:777 \
     /var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase
   sudo chmod 0400 \
     /var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase
   sudo restorecon -RF /var/lib/grayhaven/timetracker/secrets
   ```

8. Start with `sudo systemctl start grayhaven-timetracker.service`, then verify
   health, login, writes, reports, and the running image digest.

The utility attempts to restore and verify its pre-rotation database backup if
rekeying fails. Keep the service stopped until the database, deployed key, and
approved secret source are known to match. Retain the pre-rotation artifact and
old key only for the approved rollback window.

[Back to top](#operations)

## User Provisioning and Recovery

`BOOTSTRAP_USERS_FILE` is a first-install interface. Managed deployment renders
the manifest from protected configuration and installs it as a restricted
secret. The application reads it only when the user table is empty and does not
reconcile established accounts. Every bootstrap-created account must replace
its initial password at first sign-in.

After installation, administrators manage accounts in the application. A
password reset generates a strong temporary password, displays it once,
invalidates existing sessions, and requires replacement at the next sign-in.
Existing TOTP enrollment remains active.

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
finalized sessions to pending invoice and confirm that deletion is intended.
Deleted business records remain hidden from normal workflows but retain their
identifiers for controlled administrative recovery. Audit records remain
independently immutable.

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

Change the environment's managed `TZ` value to an IANA timezone and run normal
configuration convergence. Timestamps remain stored in UTC, so this changes
display and entry interpretation without rewriting stored instants. Require
the systemd service to return healthy and validate a representative report
after convergence.

[Back to top](#operations)

## Logs and Monitoring

The application emits one JSON object per line to standard error. Request,
authentication, shared-report, and state-change events include safe operational
context without passwords, TOTP values, or report tokens. The encrypted
database also contains append-only audit history available to administrators.

The managed environment owns collection, retention, dashboards, alerts, and
access controls. Its integration consumes the existing structured journald
stream rather than requiring an application-specific logging mode. Validate log
collection and alerts before the service receives real data.

Monitor persistent-volume growth because audit history is intentionally not
editable or deletable through the application.

[Back to top](#operations)
