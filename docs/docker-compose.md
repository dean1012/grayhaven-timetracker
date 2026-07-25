# Standalone Docker Compose Operations

[Return to README](../README.md)

This guide covers the repository's optional standalone/local Docker Compose
workflow. It is intended for local evaluation and adaptation. It is not the
Grayhaven managed deployment and is not a turnkey production platform. The
operator remains responsible for host hardening, TLS, secret delivery,
monitoring, off-host backups, retention, and recovery testing.

## Table of Contents

- [Startup](#startup)
- [Service Health](#service-health)
- [Online Backups](#online-backups)
- [Backup Verification](#backup-verification)
- [Database Restore](#database-restore)
- [SQLCipher Key Rotation](#sqlcipher-key-rotation)
- [Bootstrap Credential Generation](#bootstrap-credential-generation)
- [Timezone Changes](#timezone-changes)

## Startup

Create local state and secret directories, generate unique secrets, and supply
the separately licensed runtime branding and bootstrap-user manifest described
in [Configuration](configuration.md):

```bash
mkdir -p data secrets
chmod 700 data secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
  > secrets/flask_secret_key
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' \
  > secrets/sqlcipher_passphrase
chmod 600 secrets/*
docker compose up --build -d
```

The supplied Compose service binds only to `127.0.0.1:8000`. Local defaults,
keys, and branding must not be reused in a managed or public environment.

[Back to top](#standalone-docker-compose-operations)

## Service Health

Check service state and the loopback health endpoint:

```bash
docker compose ps
curl --fail http://127.0.0.1:8000/health
```

A healthy response is HTTP 200 with `{"status":"ok"}`.

[Back to top](#standalone-docker-compose-operations)

## Online Backups

Do not copy the live database while WAL activity is possible. Create an
encrypted online artifact with SQLite's backup API:

```bash
mkdir -p data/backups
docker compose exec timetracker \
  python scripts/database_maintenance.py backup \
  /app/data/timetracker.sqlite3 \
  /run/secrets/sqlcipher_passphrase \
  /app/data/backups/timetracker-$(date -u +%Y%m%dT%H%M%SZ).sqlite3
```

The utility verifies SQLCipher and SQLite integrity, writes mode `0600`, and
refuses to overwrite an existing path. Configure any external backup system to
capture only after this command succeeds.

[Back to top](#standalone-docker-compose-operations)

## Backup Verification

Verify a retained artifact with its matching key:

```bash
docker compose exec timetracker \
  python scripts/database_maintenance.py verify \
  /app/data/backups/<backup> \
  /run/secrets/sqlcipher_passphrase
```

Record the artifact checksum, application image/version, schema version, and
key version. Periodically restore the artifact to an isolated copy and verify
health, login, TOTP, representative records, reports, audit history, and a
controlled write.

[Back to top](#standalone-docker-compose-operations)

## Database Restore

Identify and verify the approved artifact, matching application build, schema,
and key. Preserve the current database generation before replacing it:

```bash
docker compose stop timetracker
rollback_dir="$(mktemp -d data/rollback.XXXXXXXX)"
for path in \
  data/timetracker.sqlite3 \
  data/timetracker.sqlite3-wal \
  data/timetracker.sqlite3-shm; do
  if test -e "$path"; then
    cp -a -- "$path" "$rollback_dir/"
  fi
done
printf 'Rollback directory: %s\n' "$rollback_dir"
rm -f -- \
  data/timetracker.sqlite3 \
  data/timetracker.sqlite3-wal \
  data/timetracker.sqlite3-shm
cp -a -- data/backups/<backup> data/timetracker.sqlite3
chown "$(id -u):$(id -g)" data/timetracker.sqlite3
chmod 0600 data/timetracker.sqlite3
docker compose start timetracker
curl --fail http://127.0.0.1:8000/health
```

Then verify login, TOTP, current records, reports, shared-report access, audit
history, and one controlled write. Retain the rollback directory and matching
old key until the restore is accepted. Remove stale WAL and SHM sidecars again
before returning a preserved prior database generation to service.

[Back to top](#standalone-docker-compose-operations)

## SQLCipher Key Rotation

Treat key rotation as offline maintenance:

1. Create and verify a current backup.
2. Stop the service with `docker compose stop timetracker`.
3. Install the proposed key as `secrets/sqlcipher_passphrase.new` with mode
   `0600`.
4. Run:

   ```bash
   docker compose run --rm --no-deps timetracker \
     python scripts/database_maintenance.py rekey \
     /app/data/timetracker.sqlite3 \
     /run/secrets/sqlcipher_passphrase \
     /run/secrets/sqlcipher_passphrase.new
   ```

5. Verify the database with the new key.
6. Atomically replace `secrets/sqlcipher_passphrase`, then start with
   `docker compose start timetracker`.
7. Validate health, login, writes, and reports.

The utility attempts to restore and verify its pre-rotation backup if rekeying
fails. Keep the service stopped until the database and active key are known to
match. Retain the pre-rotation backup and old key only for the approved rollback
window.

[Back to top](#standalone-docker-compose-operations)

## Bootstrap Credential Generation

Generate an Argon2id hash for an initial password without terminal echo:

```bash
docker compose run --rm --no-deps timetracker python -c '
from getpass import getpass
from grayhaven_timetracker.auth import hash_password
print(hash_password(getpass("Initial password: ")))
'
```

Generate an optional Base32 TOTP secret:

```bash
docker compose run --rm --no-deps timetracker \
  python -c 'import pyotp; print(pyotp.random_base32())'
```

Treat both outputs as credentials. Put them directly into the approved local
secret workflow and deliver password and TOTP enrollment information through
separate channels.

[Back to top](#standalone-docker-compose-operations)

## Timezone Changes

Set `TZ` to an IANA timezone and recreate the service:

```bash
TZ=America/Chicago docker compose up -d --force-recreate timetracker
curl --fail http://127.0.0.1:8000/health
```

Timestamps remain stored in UTC. Validate representative time entry and report
display after the change.

[Back to top](#standalone-docker-compose-operations)
