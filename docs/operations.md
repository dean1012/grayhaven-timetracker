# Operations

[Return to README.md](../README.md)

## Table of Contents

- [Service Health](#service-health)
- [Backups](#backups)
- [Restore](#restore)
- [SQLCipher Key Rotation](#sqlcipher-key-rotation)
- [Initial Administrator Reconciliation](#initial-administrator-reconciliation)
- [Timezone Changes](#timezone-changes)
- [Logs and Monitoring](#logs-and-monitoring)

## Service Health

The application exposes `/health`. It verifies that the keyed database can
answer a minimal query and returns HTTP 200 with `{"status":"ok"}`. Database
failure returns HTTP 503 without diagnostic details.

Compose publishes the application only on `127.0.0.1:8000`. Production Nginx
must deny external access to `/health` while allowing the host's monitoring
agent to query the loopback listener. The health endpoint must not be placed on
a public load-balancer route.

[Back to top](#operations)

## Backups

Do not have restic copy the live database file by itself. WAL activity can make
an uncoordinated file copy inconsistent. Create an encrypted online backup
first, then include that artifact in the host's restic source set:

```bash
mkdir -p data/backups
docker compose exec timetracker \
  python scripts/database_maintenance.py backup \
  /app/data/timetracker.sqlite3 \
  /run/secrets/sqlcipher_passphrase \
  /app/data/backups/timetracker-$(date -u +%Y%m%dT%H%M%SZ).sqlite3
```

The command uses SQLite's online backup API, verifies SQLCipher and SQLite
integrity, writes mode `0600`, and refuses to overwrite an existing file.
Configure restic automation to run this command successfully before taking the
filesystem snapshot. Apply retention to old local staging copies separately.

Verify an artifact with the current key:

```bash
docker compose exec timetracker \
  python scripts/database_maintenance.py verify \
  /app/data/backups/<backup-file> \
  /run/secrets/sqlcipher_passphrase
```

[Back to top](#operations)

## Restore

1. Stop the application.
2. Retain the current database and any `-wal` or `-shm` sidecars for forensic
   recovery.
3. Restore the selected encrypted artifact as `data/timetracker.sqlite3`.
4. Ensure the file is owned by the configured container UID and has mode
   `0600` on a Linux filesystem.
5. Verify the restored database with the matching SQLCipher key.
6. Start the application and confirm `/health`, login, active timers, and a
   representative report.

Never test a restored database with a guessed key. SQLCipher authentication
errors are expected when the key is wrong and do not identify the correct key.

[Back to top](#operations)

## SQLCipher Key Rotation

Treat key rotation as an offline maintenance operation:

1. Create and verify a current backup.
2. Stop the application with `docker compose stop timetracker`.
3. Place the proposed key in `secrets/sqlcipher_passphrase.new` with mode
   `0600`.
4. Run the rekey command in a one-off container:

   ```bash
   docker compose run --rm --no-deps timetracker \
     python scripts/database_maintenance.py rekey \
     /app/data/timetracker.sqlite3 \
     /run/secrets/sqlcipher_passphrase \
     /run/secrets/sqlcipher_passphrase.new
   ```

5. Verify the database with the new key.
6. Atomically replace the old secret file through the approved vault-driven
   deployment procedure.
7. Start the application and validate health, login, and report generation.
8. Retain the pre-rotation backup with the old key under the approved retention
   policy, then securely remove both when the rollback window closes.

The utility attempts to restore and verify its pre-rotation backup if rekeying
fails. Keep the service stopped until the database and deployed secret are
confirmed to match.

[Back to top](#operations)

## Initial Administrator Reconciliation

Deployment automation supplies the initial administrator's email, display
name, Argon2id password hash, and TOTP secret. On startup:

- The same email updates the display name.
- Changed configured authentication values update that account and invalidate
  its existing sessions.
- Unchanged configured values preserve password or TOTP changes made through
  the application.
- A different email creates a new enabled administrator and leaves the prior
  account unchanged.

After logging into a replacement account, an administrator can demote and
disable the old account. The database refuses to remove the last enabled
administrator.

[Back to top](#operations)

## Timezone Changes

Set `TZ` to an IANA timezone name and recreate the container. Stored timestamps
remain UTC, so changing the display timezone does not rewrite or damage data.
The same sessions will be rendered in the new local timezone.

[Back to top](#operations)

## Logs and Monitoring

Logs are emitted as one JSON object per line. Events include HTTP method, path,
status, elapsed microseconds, source address, user agent, and authenticated user
identifier where available. Authentication events include successful,
rejected, and rate-limited logins without passwords or TOTP values.

Future Alloy and Loki configuration should collect container standard output
and error without parsing secrets. Fail2ban can match repeated
`login_rejected` and `login_rate_limited` events once production log paths and
the reverse-proxy address model are finalized.

[Back to top](#operations)
