# Docker Compose Operations

[Return to README](../README.md)

This guide is the authoritative procedure for the repository's optional
standalone Docker Compose installation. It is intended for local evaluation
and adaptation. It is not the Grayhaven Systems LLC managed deployment and is
not a turnkey production platform. The operator is responsible for host
hardening, TLS, secret delivery, monitoring, off-host backups, retention, and
recovery testing.

Run all commands from the repository root.

Local passkey testing must open `http://localhost:8000`. The Compose definition
explicitly sets WebAuthn RP ID `localhost` and origin
`http://localhost:8000`; do not substitute `127.0.0.1`.

## Table of Contents

- [Prepare the Installation](#prepare-the-installation)
- [Build and Start the Application](#build-and-start-the-application)
- [Check Service Health](#check-service-health)
- [Manage the Service](#manage-the-service)
- [Review Logs](#review-logs)
- [Create a Backup](#create-a-backup)
- [Verify a Backup](#verify-a-backup)
- [Restore a Backup](#restore-a-backup)
- [Rotate the SQLCipher Passphrase](#rotate-the-sqlcipher-passphrase)
- [Update the Application](#update-the-application)
- [Change the Timezone](#change-the-timezone)

## Prepare the Installation

1. Create the persistent data, secret, and branding directories.

   ```bash
   install -d -m 0700 data secrets
   install -d -m 0755 branding branding/fonts
   ```

2. Build the application image before using it for credential generation.
   Replace `<version>` with the version that should appear in the interface.

   ```bash
   APP_VERSION="<version>" docker compose build timetracker
   ```

3. Generate independent Flask and SQLCipher secrets.

   ```bash
   umask 077
   python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
     > secrets/flask_secret_key
   python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
     > secrets/sqlcipher_passphrase
   chmod 0600 secrets/flask_secret_key secrets/sqlcipher_passphrase
   ```

4. Generate an Argon2id hash for the initial administrator password. Enter the
   password when prompted and copy the resulting hash.

   ```bash
   docker compose run --rm --no-deps timetracker python -c '
   from getpass import getpass
   from grayhaven_timetracker.auth import hash_password
   print(hash_password(getpass("Initial password: ")))
   '
   ```

5. Create the bootstrap-user manifest from the supplied structural example.

   ```bash
   install -m 0600 \
     examples/bootstrap_users.sample.json \
     secrets/bootstrap_users
   "${EDITOR:-vi}" secrets/bootstrap_users
   ```

   Replace every placeholder. Set the administrator's `password_hash` to the
   hash generated in step 4. Leave `totp_secret` as `null` unless an existing
   Base32 TOTP secret is intentionally being supplied. The application rejects
   a manifest without an enabled administrator.

6. Copy an authorized branding bundle into `branding/`. Replace
   `<branding-source>` with the directory containing the assets.

   ```bash
   install -m 0644 <branding-source>/grayhaven-logo-wordmark-dark.svg \
     branding/grayhaven-logo-wordmark-dark.svg
   install -m 0644 <branding-source>/favicon.ico branding/favicon.ico
   install -m 0644 <branding-source>/favicon-16.png branding/favicon-16.png
   install -m 0644 <branding-source>/favicon-32.png branding/favicon-32.png
   install -m 0644 <branding-source>/apple-touch-icon.png \
     branding/apple-touch-icon.png
   install -m 0644 <branding-source>/fonts/inter-400.ttf \
     branding/fonts/inter-400.ttf
   install -m 0644 <branding-source>/fonts/inter-500.ttf \
     branding/fonts/inter-500.ttf
   install -m 0644 <branding-source>/fonts/inter-600.ttf \
     branding/fonts/inter-600.ttf
   install -m 0644 <branding-source>/fonts/inter-700.ttf \
     branding/fonts/inter-700.ttf
   ```

   External adopters must use branding they are authorized to distribute and
   may need to adapt the application templates and styles for a different
   identity.

7. Confirm that every required runtime file exists.

   ```bash
   test -s secrets/flask_secret_key
   test -s secrets/sqlcipher_passphrase
   test -s secrets/bootstrap_users
   test -s branding/grayhaven-logo-wordmark-dark.svg
   test -s branding/favicon.ico
   test -s branding/favicon-16.png
   test -s branding/favicon-32.png
   test -s branding/apple-touch-icon.png
   test -s branding/fonts/inter-400.ttf
   test -s branding/fonts/inter-500.ttf
   test -s branding/fonts/inter-600.ttf
   test -s branding/fonts/inter-700.ttf
   ```

[Back to top](#docker-compose-operations)

## Build and Start the Application

1. Validate the resolved Compose configuration.

   ```bash
   docker compose config --quiet
   ```

2. Build and start the service. Replace `<version>` with the application
   version that should appear in the interface.

   ```bash
   APP_VERSION="<version>" docker compose up --build --detach
   ```

3. Wait for the container health check to report `healthy`.

   ```bash
   docker compose ps
   ```

4. Query the loopback health endpoint.

   ```bash
   curl --fail --silent --show-error http://127.0.0.1:8000/health
   ```

5. Open the application in a browser.

   ```text
   http://127.0.0.1:8000
   ```

The Compose definition binds only to `127.0.0.1:8000`. Do not expose this
plain-HTTP listener directly to an untrusted network.

[Back to top](#docker-compose-operations)

## Check Service Health

1. Display the container state and health result.

   ```bash
   docker compose ps
   ```

2. Query the application health endpoint.

   ```bash
   curl --fail --silent --show-error http://127.0.0.1:8000/health
   ```

A healthy application returns `{"status":"ok"}`. The application returns
HTTP 503 if it cannot query the encrypted database.

[Back to top](#docker-compose-operations)

## Manage the Service

Stop the application without removing its container:

```bash
docker compose stop timetracker
```

Start the existing container:

```bash
docker compose start timetracker
```

Restart the application:

```bash
docker compose restart timetracker
```

Stop and remove the container without deleting persistent data or secrets:

```bash
docker compose down
```

Never add `--volumes` to the final command unless permanent data deletion is
intended and separately approved.

[Back to top](#docker-compose-operations)

## Review Logs

Display the most recent application log entries:

```bash
docker compose logs --tail 200 timetracker
```

Follow new application log entries during a controlled reproduction:

```bash
docker compose logs --follow timetracker
```

[Back to top](#docker-compose-operations)

## Create a Backup

1. Confirm that the application is healthy.

   ```bash
   docker compose ps
   curl --fail --silent --show-error http://127.0.0.1:8000/health
   ```

2. Create the backup directory.

   ```bash
   install -d -m 0700 data/backups
   ```

3. Create a timestamped encrypted snapshot with SQLite's online backup API.

   ```bash
   BACKUP_NAME="timetracker-$(date -u +%Y%m%dT%H%M%SZ).sqlite3"
   docker compose exec timetracker \
     python scripts/database_maintenance.py backup \
     /app/data/timetracker.sqlite3 \
     /run/secrets/sqlcipher_passphrase \
     "/app/data/backups/${BACKUP_NAME}"
   ```

4. Record the checksum and application version with the backup artifact.

   ```bash
   sha256sum "data/backups/${BACKUP_NAME}"
   docker compose exec timetracker printenv APP_VERSION
   ```

The backup command verifies SQLCipher and SQLite integrity, writes the artifact
with mode `0600`, and refuses to overwrite an existing path. Configure an
off-host backup system to capture `data/backups/` only after this command
succeeds. Do not copy `data/timetracker.sqlite3` while the application is
running.

[Back to top](#docker-compose-operations)

## Verify a Backup

1. Select the exact artifact to verify.

   ```bash
   BACKUP_NAME="<backup>"
   test -f "data/backups/${BACKUP_NAME}"
   ```

2. Verify the encrypted artifact with its matching SQLCipher passphrase.

   ```bash
   docker compose exec timetracker \
     python scripts/database_maintenance.py verify \
     "/app/data/backups/${BACKUP_NAME}" \
     /run/secrets/sqlcipher_passphrase
   ```

3. Record the checksum after verification.

   ```bash
   sha256sum "data/backups/${BACKUP_NAME}"
   ```

Periodically restore a verified artifact into an isolated installation and
verify health, login, TOTP, representative records, billing metadata, reports,
shared-report access, audit history, and one controlled write.

[Back to top](#docker-compose-operations)

## Restore a Backup

1. Select and verify the exact artifact before stopping the service.

   ```bash
   BACKUP_NAME="<backup>"
   test -f "data/backups/${BACKUP_NAME}"
   docker compose exec timetracker \
     python scripts/database_maintenance.py verify \
     "/app/data/backups/${BACKUP_NAME}" \
     /run/secrets/sqlcipher_passphrase
   ```

2. Stop the application and confirm that it is not running.

   ```bash
   docker compose stop timetracker
   test "$(docker compose ps --status running --quiet timetracker)" = ""
   ```

3. Preserve the current database, WAL, and SHM files in a rollback directory.

   ```bash
   ROLLBACK_DIR="$(mktemp -d data/rollback.XXXXXXXX)"
   find data \
     -maxdepth 1 \
     -type f \
     \( -name 'timetracker.sqlite3' \
        -o -name 'timetracker.sqlite3-wal' \
        -o -name 'timetracker.sqlite3-shm' \) \
     -exec cp -a -t "$ROLLBACK_DIR" -- {} +
   printf 'Rollback directory: %s\n' "$ROLLBACK_DIR"
   ```

4. Remove the old database and sidecars, then install the verified artifact.

   ```bash
   rm -f -- \
     data/timetracker.sqlite3 \
     data/timetracker.sqlite3-wal \
     data/timetracker.sqlite3-shm
   cp -a -- "data/backups/${BACKUP_NAME}" data/timetracker.sqlite3
   chmod 0600 data/timetracker.sqlite3
   ```

5. Start the application and verify its health.

   ```bash
   docker compose start timetracker
   docker compose ps
   curl --fail --silent --show-error http://127.0.0.1:8000/health
   ```

6. Verify administrator login, TOTP, current records, billing metadata,
   reports, shared-report access, audit history, and one controlled write.
   Retain the rollback directory and prior passphrase until the restore is
   accepted.

If validation fails, stop the service, remove the failed database and its
sidecars, copy the complete prior generation from the printed rollback
directory into `data/`, and start the service again.

[Back to top](#docker-compose-operations)

## Rotate the SQLCipher Passphrase

1. Create and verify a current backup by following
   [Create a Backup](#create-a-backup) and
   [Verify a Backup](#verify-a-backup).

2. Generate the proposed passphrase in a separate secret file.

   ```bash
   umask 077
   python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
     > secrets/sqlcipher_passphrase.new
   chmod 0600 secrets/sqlcipher_passphrase.new
   ```

3. Stop the application and confirm that it is not running.

   ```bash
   docker compose stop timetracker
   test "$(docker compose ps --status running --quiet timetracker)" = ""
   ```

4. Preserve the current database, sidecars, and passphrase in a rollback
   directory.

   ```bash
   ROLLBACK_DIR="$(mktemp -d data/rekey-rollback.XXXXXXXX)"
   cp -a secrets/sqlcipher_passphrase "$ROLLBACK_DIR/"
   find data \
     -maxdepth 1 \
     -type f \
     \( -name 'timetracker.sqlite3' \
        -o -name 'timetracker.sqlite3-wal' \
        -o -name 'timetracker.sqlite3-shm' \) \
     -exec cp -a -t "$ROLLBACK_DIR" -- {} +
   printf 'Rollback directory: %s\n' "$ROLLBACK_DIR"
   ```

5. Rekey the database with a one-off container.

   ```bash
   docker compose run --rm --no-deps timetracker \
     python scripts/database_maintenance.py rekey \
     /app/data/timetracker.sqlite3 \
     /run/secrets/sqlcipher_passphrase \
     /run/secrets/sqlcipher_passphrase.new
   ```

6. Verify the database with the proposed passphrase.

   ```bash
   docker compose run --rm --no-deps timetracker \
     python scripts/database_maintenance.py verify \
     /app/data/timetracker.sqlite3 \
     /run/secrets/sqlcipher_passphrase.new
   ```

7. Replace the active passphrase file.

   ```bash
   mv -f -- \
     secrets/sqlcipher_passphrase.new \
     secrets/sqlcipher_passphrase
   chmod 0600 secrets/sqlcipher_passphrase
   ```

8. Recreate the container so the read-only secret mount uses the new file,
   then verify health.

   ```bash
   docker compose up --detach --force-recreate timetracker
   docker compose ps
   curl --fail --silent --show-error http://127.0.0.1:8000/health
   ```

9. Verify login, writes, and reports. Retain the rollback directory and old
   passphrase until the rotation is accepted.

If rekeying fails, keep the application stopped. Restore the database,
sidecars, and passphrase from the rollback directory before restarting it.

[Back to top](#docker-compose-operations)

## Update the Application

1. Create and verify a current backup by following
   [Create a Backup](#create-a-backup) and
   [Verify a Backup](#verify-a-backup).

2. Fetch the intended source revision and review it before changing the
   running application.

   ```bash
   git fetch --prune origin
   git status --short --branch
   git log --show-signature -1 <approved-ref>
   ```

3. Check out the approved revision.

   ```bash
   git switch --detach <approved-ref>
   ```

4. Validate the resolved Compose configuration and build the new image.

   ```bash
   docker compose config --quiet
   APP_VERSION="<version>" docker compose build timetracker
   ```

5. Recreate the service with the new image.

   ```bash
   APP_VERSION="<version>" docker compose up --detach --force-recreate timetracker
   ```

6. Verify container health, the application endpoint, login, and a
   representative read and write.

   ```bash
   docker compose ps
   curl --fail --silent --show-error http://127.0.0.1:8000/health
   ```

If the update cannot be accepted, return to the previously recorded source
revision and application version, rebuild and recreate the service, and restore
the matching database and passphrase when the update changed persistent data.

[Back to top](#docker-compose-operations)

## Change the Timezone

1. Set `TZ` to the required IANA timezone and recreate the service.

   ```bash
   TZ="<Area/Location>" docker compose up --detach --force-recreate timetracker
   ```

2. Verify health after the container is recreated.

   ```bash
   docker compose ps
   curl --fail --silent --show-error http://127.0.0.1:8000/health
   ```

3. Verify a representative time entry and report in the application.

Timestamps remain stored in UTC. Changing `TZ` changes display and entry
interpretation without rewriting stored timestamps.

[Back to top](#docker-compose-operations)
