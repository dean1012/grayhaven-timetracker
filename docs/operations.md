# Operations

[Return to README.md](../README.md)

## Table of Contents

- [Service Health](#service-health)
- [Production Origin and Proxy](#production-origin-and-proxy)
- [Backups](#backups)
- [Restore](#restore)
- [SQLCipher Key Rotation](#sqlcipher-key-rotation)
- [Deployment-Managed User Reconciliation](#deployment-managed-user-reconciliation)
- [No-Email User Recovery](#no-email-user-recovery)
- [Live Client Reports](#live-client-reports)
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

## Production Origin and Proxy

Set the external origin and browser trust boundary explicitly in production:

```text
PUBLIC_BASE_URL=https://timetracker.example.invalid
SESSION_COOKIE_SECURE=true
TRUSTED_HOSTS=timetracker.example.invalid
TRUSTED_PROXY_COUNT=1
```

Replace the example origin and proxy count with each deployment target's
values. Confirm the proxy count against the final staging request path. The
application refuses an external `PUBLIC_BASE_URL` unless Secure cookies are
enabled and its hostname matches `TRUSTED_HOSTS`. Configure Nginx to preserve
the original Host and send the expected forwarded address and scheme headers.
Do not increase `TRUSTED_PROXY_COUNT` beyond the exact number of trusted proxy
hops. Leave the cookie domain unset so authentication cookies remain host-only
to the selected deployment origin and are not shared with sibling subdomains.

The application redacts live report tokens from its own logs. Configure the
reverse proxy to redact `/shared/reports/<token>` paths as well, because proxy
access logs are outside the application logger.

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
integrity, writes mode `0600`, and refuses to overwrite an existing file. The
backup includes the append-only audit history.
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

## Deployment-Managed User Reconciliation

For local UAT, deployment automation can supply one initial administrator's
email, display name, and Argon2id password hash through the `INITIAL_ADMIN_*`
settings. The TOTP secret is optional; omission creates the account without
TOTP so the administrator can enroll it from **Profile** after login.

The production-oriented interface is `BOOTSTRAP_USERS_FILE`. Ansible should
render a JSON list from encrypted Grayhaven vault data, validate it before
deployment, install it as a permission-restricted secret file with `no_log`,
and point the container at the installed path. This mirrors the existing
vault-to-htpasswd workflow while allowing structured application attributes.
Each entry requires email, first name, last name, Argon2id password hash, and
an `admin` or `user` role. The enabled flag defaults to true, and TOTP is
optional per account.

On startup:

- missing accounts are created as administrators or standard users;
- names, roles, and enabled states are reconciled every time;
- changed configured password or TOTP fingerprints update authentication and
  invalidate existing sessions;
- unchanged credential fingerprints preserve in-application password and TOTP
  changes;
- omitted TOTP values never remove an authenticator enrolled from **Profile**;
- disabling an account stops its active timer; and
- each account reconciliation is recorded as a system audit event without
  credential material.

At least one configured account must be an enabled administrator. To retire an
account, retain its manifest entry with `enabled: false`; this preserves time
and audit history. Removing an entry only stops deployment management and does
not delete or disable the database account. The database independently refuses
to remove the last enabled administrator.

[Back to top](#operations)

## No-Email User Recovery

The application sends no email. An administrator can open **Users**, select
**Reset password**, and re-enter their own current password and TOTP code. A
successful reset:

- generates a strong temporary password and displays it once;
- stores only its Argon2id hash;
- invalidates the user's existing application sessions;
- requires the user to replace it immediately after sign-in; and
- preserves the user's existing TOTP secret.

TOTP codes are single-use. If the administrator just used the current code to
sign in, wait for the authenticator to display its next code before confirming
a password reset or other credential rotation.

Deliver the temporary password through an approved channel separate from any
TOTP provisioning information. If the user has also lost the configured TOTP
method, password reset alone cannot restore access. Recovery then requires the
authorized offline procedure; there is no email fallback or administrator TOTP
override in the application.

[Back to top](#operations)

## Live Client Reports

Client reports do not require account registration. Client creation generates a
permanent report URL automatically, even before any contracts exist. Only
administrators can view or share that URL from the client page. Until a password
is generated, the URL cannot grant report access. The page provides copy and
mailto sharing controls. The link-sharing mailto includes the URL and states
that the password will arrive separately.

An administrator can select **Generate Password** from the client page. After
password and TOTP reauthentication, the confirmation page displays the new
password once with copy and Proton Mail actions inside the password field. The
password mailto includes the reset password and permanent report URL. The
administrator must send that draft as a Proton password-protected encrypted
message. Generate a second temporary password for decrypting the email and
deliver it through a separate approved channel. The email-decryption password
is distinct from the client report password and is not generated or stored by
the application. The report password cannot be recovered after leaving the
confirmation page.

Resetting the client report password requires administrator password and TOTP
reauthentication. It displays a new password once and invalidates existing
report browser sessions for every contract under that client. Stored report
passwords cannot be viewed or recovered.

The shared page is the same live dashboard available to administrators. Active
contract sections are shown newest first. Active session duration and allocated
cost advance every second. A same-origin
background check discovers new, stopped, edited, or deleted timers within a
few seconds and updates the report without a page reload. Password replacement
or session expiry ends synchronization and freezes the visible values.

PDF reports are static. Generation includes active timers through the exact
generation instant but does not stop or otherwise modify those timers.

[Back to top](#operations)

## Timezone Changes

Set `TZ` to an IANA timezone name and recreate the container. Stored timestamps
remain UTC, so changing the display timezone does not rewrite or damage data.
The same sessions will be rendered in the new local timezone.

[Back to top](#operations)

## Logs and Monitoring

Logs are emitted as one JSON object per line. Access events include HTTP method,
redacted path, status, elapsed microseconds, source address, user agent, and
authenticated user identifier where available. Authentication events include
accepted password stages, successful logins, expired challenges, and rejected
or rate-limited attempts without passwords or TOTP values. Unchanged live
report conditional checks return HTTP 304 and are omitted from access and
persistent audit records; the initial view, changed report responses, access
failures, and underlying timer actions remain recorded.

The encrypted database also contains an append-only audit history available to
administrators under **Audit**. It records authenticated requests, protected
public-report activity, semantic state changes, administrator recovery actions,
and application startup or bootstrap events. There is no application delete or
edit operation for audit events, and database triggers reject either change.
Monitor persistent-volume capacity because audit history grows with use.

Future Alloy and Loki configuration should collect container standard output
and error and select the `grayhaven_timetracker.audit` logger for canonical
audit events. Those JSON records already contain source, actor, request, status,
and safe structured details. Fail2ban can match repeated `login_rejected`,
`login_rate_limited`, shared-report rejection, and sensitive-action
rate-limited events once production log paths and the reverse-proxy address
model are finalized.

[Back to top](#operations)
