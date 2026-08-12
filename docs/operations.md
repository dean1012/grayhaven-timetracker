# Operations

[Return to README](../README.md)

This runbook covers application-specific operations on a Grayhaven Systems LLC
managed host. Provisioning, reverse-proxy configuration, secrets, image
selection, scheduled backups, and monitoring are managed by the deployment
repositories. For a standalone installation, use the
[Docker Compose operations guide](docker-compose.md).

Run these procedures on the managed web host unless a step says otherwise.

## Table of Contents

- [Check Service Health](#check-service-health)
- [Manage the Service](#manage-the-service)
- [Verify a Database Schema Upgrade](#verify-a-database-schema-upgrade)
- [Create a Backup](#create-a-backup)
- [Verify a Local Backup](#verify-a-local-backup)
- [Test Backup and Restore with grayhaven-backupctl](#test-backup-and-restore-with-grayhaven-backupctl)
- [Restore a Local Backup](#restore-a-local-backup)
- [Restore a Backup from Restic](#restore-a-backup-from-restic)
- [Rotate the SQLCipher Passphrase](#rotate-the-sqlcipher-passphrase)
- [Provision and Recover Users](#provision-and-recover-users)
- [Manage and Recover Passkeys](#manage-and-recover-passkeys)
- [Correct Contract and Billing Records](#correct-contract-and-billing-records)
- [Manage Shared Client Reports](#manage-shared-client-reports)
- [Change the Timezone](#change-the-timezone)
- [Review Logs](#review-logs)

## Check Service Health

1. Set the public hostname used by the deployed application.

   ```bash
   TIMETRACKER_HOST="<configured-hostname>"
   ```

2. Confirm that the systemd service is active.

   ```bash
   sudo systemctl is-active grayhaven-timetracker.service
   sudo systemctl status grayhaven-timetracker.service --no-pager
   ```

3. Confirm that the container is running the expected immutable image digest.

   ```bash
   sudo podman container inspect \
     --format '{{.ImageName}} {{.ImageDigest}}' \
     grayhaven-timetracker
   ```

4. Query the application health endpoint through the loopback listener with
   the trusted public Host header.

   ```bash
   curl --fail --silent --show-error \
     --header "Host: ${TIMETRACKER_HOST}" \
     http://127.0.0.1:8000/health
   ```

A healthy application returns `{"status":"ok"}`. The application returns
HTTP 503 if it cannot query the encrypted database. It returns HTTP 400 when
the Host header is not trusted.

[Back to top](#operations)

## Manage the Service

Use systemd for every lifecycle operation. Do not use `podman stop` or
`podman start`; systemd owns the container and treats a direct container stop
as an unexpected exit.

Stop the application before offline database or key maintenance:

```bash
sudo systemctl stop grayhaven-timetracker.service
sudo systemctl is-active grayhaven-timetracker.service
```

The second command must report `inactive` before files under
`/var/lib/grayhaven/timetracker/data` or
`/var/lib/grayhaven/timetracker/secrets` are changed.

Start the application after maintenance:

```bash
sudo systemctl start grayhaven-timetracker.service
sudo systemctl is-active grayhaven-timetracker.service
```

Restart the application without changing its deployed configuration:

```bash
sudo systemctl restart grayhaven-timetracker.service
sudo systemctl is-active grayhaven-timetracker.service
```

[Back to top](#operations)

## Verify a Database Schema Upgrade

The application applies supported schema migrations during normal startup.
Image selection and deployment remain controlled by the managed configuration
system; this procedure verifies the application-specific database result.

1. Before deployment, record the current image digest and schema version.

   ```bash
   sudo podman container inspect \
     --format '{{.ImageName}} {{.ImageDigest}}' \
     grayhaven-timetracker
   sudo podman exec -i grayhaven-timetracker python - <<'PY'
   from pathlib import Path

   from grayhaven_timetracker.database import connect_sqlcipher

   key = Path("/run/secrets/sqlcipher_passphrase").read_text().rstrip("\r\n")
   connection = connect_sqlcipher(
       Path("/app/data/timetracker.sqlite3"), key
   )
   try:
       row = connection.execute(
           "SELECT version FROM schema_version WHERE id = 1"
       ).fetchone()
       if row is None:
           raise SystemExit("Schema version marker is missing")
       print(row[0])
   finally:
       connection.close()
   PY
   ```

2. Create and verify a current encrypted recovery artifact by following
   [Create a Backup](#create-a-backup) and
   [Verify a Local Backup](#verify-a-local-backup). Preserve its checksum,
   image digest, schema version, and SQLCipher key version for the complete
   rollback window.

3. After the managed deployment completes, confirm the service, target image,
   application health, and new schema version.

   ```bash
   TIMETRACKER_HOST="<configured-hostname>"
   sudo systemctl is-active --quiet grayhaven-timetracker.service
   sudo podman container inspect \
     --format '{{.ImageName}} {{.ImageDigest}}' \
     grayhaven-timetracker
   curl --fail --silent --show-error \
     --header "Host: ${TIMETRACKER_HOST}" \
     http://127.0.0.1:8000/health
   sudo podman exec -i grayhaven-timetracker python - <<'PY'
   from pathlib import Path

   from grayhaven_timetracker.database import connect_sqlcipher

   key = Path("/run/secrets/sqlcipher_passphrase").read_text().rstrip("\r\n")
   connection = connect_sqlcipher(
       Path("/app/data/timetracker.sqlite3"), key
   )
   try:
       row = connection.execute(
           "SELECT version FROM schema_version WHERE id = 1"
       ).fetchone()
       if row is None:
           raise SystemExit("Schema version marker is missing")
       print(row[0])
   finally:
       connection.close()
   PY
   ```

4. Sign in and verify existing users, representative work records, billing
   metadata, reports, shared-report access, and audit history. Complete one
   controlled write and confirm its audit event.

5. Restart the same image and prove startup is idempotent.

   ```bash
   sudo systemctl restart grayhaven-timetracker.service
   sudo systemctl is-active --quiet grayhaven-timetracker.service
   curl --fail --silent --show-error \
     --header "Host: ${TIMETRACKER_HOST}" \
     http://127.0.0.1:8000/health
   ```

If migration fails, keep the service stopped and review its logs. Do not
repeatedly restart it. A migration transaction retains the prior schema when it
fails, while successful migration may require restoring the recorded
pre-upgrade artifact before an older image can run.

[Back to top](#operations)

## Create a Backup

1. Confirm that the application is active. The managed backup hook refuses to
   snapshot an inactive application.

   ```bash
   sudo systemctl is-active grayhaven-timetracker.service
   ```

2. Create the application snapshot and run the configured local and remote
   host backup workflow.

   ```bash
   sudo grayhaven-backupctl backup
   ```

3. List the application artifacts created by the backup hook.

   ```bash
   sudo find /var/lib/grayhaven/timetracker/backups \
     -maxdepth 1 \
     -type f \
     -name 'timetracker-*.sqlite3' \
     -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' \
     | sort
   ```

4. List the restic snapshots and record the snapshot ID that contains the new
   artifact.

   ```bash
   sudo grayhaven-backupctl list
   ```

The backup hook uses SQLite's online backup API, verifies SQLCipher and SQLite
integrity, and atomically publishes the encrypted artifact under
`/var/lib/grayhaven/timetracker/backups`. Restic captures that directory. The
live database and its WAL and SHM sidecars are intentionally excluded. Never
copy the live database as a substitute for this procedure.

[Back to top](#operations)

## Verify a Local Backup

1. Select the exact backup artifact to verify.

   ```bash
   BACKUP="/var/lib/grayhaven/timetracker/backups/<backup>"
   ```

2. Confirm that the selected path is a regular file.

   ```bash
   sudo test -f "$BACKUP"
   ```

3. Verify the encrypted artifact with the running approved container and its
   deployed SQLCipher passphrase.

   ```bash
   sudo podman exec grayhaven-timetracker \
     python scripts/database_maintenance.py verify \
     "/app/backups/$(basename "$BACKUP")" \
     /run/secrets/sqlcipher_passphrase
   ```

4. Record the artifact checksum with the application image digest and restic
   snapshot ID for the recovery point.

   ```bash
   sudo sha256sum "$BACKUP"
   sudo podman container inspect \
     --format '{{.ImageName}} {{.ImageDigest}}' \
     grayhaven-timetracker
   sudo grayhaven-backupctl list
   ```

[Back to top](#operations)

## Test Backup and Restore with `grayhaven-backupctl`

Use a disposable recovery host or isolated container environment. Do not test
a restore over the live database.

1. Create a new backup and record its artifact name, checksum, restic snapshot
   ID, application image digest, schema version, and SQLCipher key version.

   ```bash
   sudo grayhaven-backupctl backup
   sudo grayhaven-backupctl list
   sudo find /var/lib/grayhaven/timetracker/backups \
     -maxdepth 1 -type f -name 'timetracker-*.sqlite3' -printf '%T@ %p\n' \
     | sort -n
   ```

2. Confirm that the selected restic snapshot contains the artifact.

   ```bash
   sudo grayhaven-backupctl ls <snapshot> \
     --path /var/lib/grayhaven/timetracker/backups \
     --recursive
   ```

3. Restore the backup directory into an isolated target.

   ```bash
   sudo grayhaven-backupctl restore <snapshot> \
     --target /tmp \
     --path /var/lib/grayhaven/timetracker/backups
   ```

4. Verify the restored artifact with the exact image and SQLCipher passphrase
   recorded for that recovery point.

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

5. Create a disposable data directory and install the restored artifact.

   ```bash
   sudo install -d -o 777 -g 777 -m 0700 \
     /tmp/timetracker-recovery-data
   sudo cp -a \
     /tmp/var/lib/grayhaven/timetracker/backups/<backup> \
     /tmp/timetracker-recovery-data/timetracker.sqlite3
   sudo chown 777:777 \
     /tmp/timetracker-recovery-data/timetracker.sqlite3
   sudo chmod 0600 \
     /tmp/timetracker-recovery-data/timetracker.sqlite3
   ```

6. Start the recorded image as an isolated recovery container on loopback port
   18000.

   ```bash
   sudo podman run --detach --rm \
     --name grayhaven-timetracker-recovery \
     --user 777:777 \
     --read-only \
     --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
     --cap-drop all \
     --security-opt no-new-privileges \
     --publish 127.0.0.1:18000:8000 \
     --env BRANDING_PATH=/app/branding \
     --env DATABASE_PATH=/app/data/timetracker.sqlite3 \
     --env SECRET_KEY_FILE=/run/secrets/flask_secret_key \
     --env SKIP_BOOTSTRAP=true \
     --env SQLCIPHER_PASSPHRASE_FILE=/run/secrets/sqlcipher_passphrase \
     --env TRUSTED_HOSTS=localhost,127.0.0.1 \
     --volume /tmp/timetracker-recovery-data:/app/data:Z \
     --volume /var/lib/grayhaven/timetracker/branding:/app/branding:ro,Z \
     --volume /var/lib/grayhaven/timetracker/secrets:/run/secrets:ro,Z \
     <approved-image>@sha256:<digest>
   ```

7. Query only the isolated container's loopback health endpoint.

   ```bash
   curl --fail --silent --show-error http://127.0.0.1:18000/health
   ```

   A successful response confirms that the application started and loaded the
   restored database with the supplied SQLCipher passphrase.

8. Stop the recovery container and remove the isolated recovery files after
   the exercise is accepted.

   ```bash
   sudo podman stop grayhaven-timetracker-recovery
   sudo rm -rf /tmp/timetracker-recovery-data
   sudo rm -f /tmp/var/lib/grayhaven/timetracker/backups/<backup>
   ```

[Back to top](#operations)

## Restore a Local Backup

Use this procedure when the selected artifact already exists under
`/var/lib/grayhaven/timetracker/backups`.

1. Set the selected artifact and public hostname.

   ```bash
   BACKUP="/var/lib/grayhaven/timetracker/backups/<backup>"
   TIMETRACKER_HOST="<configured-hostname>"
   ```

2. Verify the artifact before stopping the application.

   ```bash
   sudo podman exec grayhaven-timetracker \
     python scripts/database_maintenance.py verify \
     "/app/backups/$(basename "$BACKUP")" \
     /run/secrets/sqlcipher_passphrase
   ```

3. Stop the systemd service and require it to be inactive.

   ```bash
   sudo systemctl stop grayhaven-timetracker.service
   test "$(sudo systemctl is-active grayhaven-timetracker.service)" = inactive
   ```

4. Preserve the complete current database generation in a root-only rollback
   directory.

   ```bash
   ROLLBACK_DIR="$(sudo mktemp -d \
     /var/lib/grayhaven/timetracker/rollback.XXXXXXXX)"
   sudo find /var/lib/grayhaven/timetracker/data \
     -maxdepth 1 \
     -type f \
     \( -name 'timetracker.sqlite3' \
        -o -name 'timetracker.sqlite3-wal' \
        -o -name 'timetracker.sqlite3-shm' \) \
     -exec cp -a -t "$ROLLBACK_DIR" -- {} +
   printf 'Rollback directory: %s\n' "$ROLLBACK_DIR"
   ```

5. Remove the old database and sidecars, then install the selected artifact.

   ```bash
   sudo rm -f -- \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3 \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3-wal \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3-shm
   sudo cp -a "$BACKUP" \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
   ```

6. Restore the managed ownership, permissions, and SELinux context.

   ```bash
   sudo chown 777:777 \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
   sudo chmod 0600 \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
   sudo restorecon -RF /var/lib/grayhaven/timetracker/data
   ```

7. Start the service and verify its health and image digest.

   ```bash
   sudo systemctl start grayhaven-timetracker.service
   sudo systemctl is-active --quiet grayhaven-timetracker.service
   curl --fail --silent --show-error \
     --header "Host: ${TIMETRACKER_HOST}" \
     http://127.0.0.1:8000/health
   sudo podman container inspect \
     --format '{{.ImageName}} {{.ImageDigest}}' \
     grayhaven-timetracker
   ```

[Back to top](#operations)

## Restore a Backup from Restic

Use this procedure when the required artifact is not present under
`/var/lib/grayhaven/timetracker/backups`.

1. Find the snapshot that contains the required backup directory.

   ```bash
   sudo grayhaven-backupctl find \
     --path /var/lib/grayhaven/timetracker/backups
   ```

2. Inspect the matching snapshot and choose the exact artifact to restore.

   ```bash
   sudo grayhaven-backupctl ls <snapshot> \
     --path /var/lib/grayhaven/timetracker/backups \
     --recursive
   ```

3. Restore the backup directory beneath `/tmp`. Replace `<snapshot>` with the
   chosen snapshot ID. Use `latest` only when the newest matching snapshot is
   the intended recovery point.

   ```bash
   sudo grayhaven-backupctl restore <snapshot> \
     --target /tmp \
     --path /var/lib/grayhaven/timetracker/backups
   ```

   To explicitly restore the latest matching snapshot, run:

   ```bash
   sudo grayhaven-backupctl restore latest \
     --target /tmp \
     --path /var/lib/grayhaven/timetracker/backups
   ```

   The backup utility preserves the absolute path below the target. The
   restored artifact is therefore located at
   `/tmp/var/lib/grayhaven/timetracker/backups/<backup>`.
   The [`grayhaven-backupctl` operations guide](https://github.com/dean1012/grayhaven-backupctl/blob/main/docs/operations.md#restoring-to-a-target-directory)
   documents additional snapshot selectors and overwrite behavior.

4. Verify the restored artifact with the approved image and matching deployed
   SQLCipher passphrase.

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

5. Set the restored artifact path and public hostname.

   ```bash
   BACKUP="/tmp/var/lib/grayhaven/timetracker/backups/<backup>"
   TIMETRACKER_HOST="<configured-hostname>"
   ```

6. Stop the systemd service and require it to be inactive.

   ```bash
   sudo systemctl stop grayhaven-timetracker.service
   test "$(sudo systemctl is-active grayhaven-timetracker.service)" = inactive
   ```

7. Preserve the complete current database generation in a root-only rollback
   directory.

   ```bash
   ROLLBACK_DIR="$(sudo mktemp -d \
     /var/lib/grayhaven/timetracker/rollback.XXXXXXXX)"
   sudo find /var/lib/grayhaven/timetracker/data \
     -maxdepth 1 \
     -type f \
     \( -name 'timetracker.sqlite3' \
        -o -name 'timetracker.sqlite3-wal' \
        -o -name 'timetracker.sqlite3-shm' \) \
     -exec cp -a -t "$ROLLBACK_DIR" -- {} +
   printf 'Rollback directory: %s\n' "$ROLLBACK_DIR"
   ```

8. Remove the old database and sidecars, then install the restored artifact.

   ```bash
   sudo rm -f -- \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3 \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3-wal \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3-shm
   sudo cp -a "$BACKUP" \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
   ```

9. Restore the managed ownership, permissions, and SELinux context.

   ```bash
   sudo chown 777:777 \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
   sudo chmod 0600 \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3
   sudo restorecon -RF /var/lib/grayhaven/timetracker/data
   ```

10. Start the service and verify its health and image digest.

    ```bash
    sudo systemctl start grayhaven-timetracker.service
    sudo systemctl is-active --quiet grayhaven-timetracker.service
    curl --fail --silent --show-error \
      --header "Host: ${TIMETRACKER_HOST}" \
      http://127.0.0.1:8000/health
    sudo podman container inspect \
      --format '{{.ImageName}} {{.ImageDigest}}' \
      grayhaven-timetracker
    ```

11. Remove the temporary restored artifact after the restored application and
    its rollback window are accepted.

    ```bash
    sudo rm -f /tmp/var/lib/grayhaven/timetracker/backups/<backup>
    ```

[Back to top](#operations)

## Rotate the SQLCipher Passphrase

Coordinate this procedure with the encrypted configuration source. Do not
change the managed secret value before the database has been rekeyed.

1. Create and verify a current backup by following
   [Create a Backup](#create-a-backup) and
   [Verify a Local Backup](#verify-a-local-backup).

2. Install the proposed passphrase through the approved secret-delivery
   process at the following path:

   ```text
   /var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase.new
   ```

3. Apply the managed owner, mode, and SELinux context to the proposed key.

   ```bash
   sudo chown 777:777 \
     /var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase.new
   sudo chmod 0400 \
     /var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase.new
   sudo restorecon -RF /var/lib/grayhaven/timetracker/secrets
   ```

4. Record the running image and stop the application.

   ```bash
   sudo podman container inspect \
     --format '{{.ImageName}} {{.ImageDigest}}' \
     grayhaven-timetracker
   sudo systemctl stop grayhaven-timetracker.service
   test "$(sudo systemctl is-active grayhaven-timetracker.service)" = inactive
   ```

5. Preserve the database, sidecars, and current passphrase in a root-only
   rollback directory.

   ```bash
   ROLLBACK_DIR="$(sudo mktemp -d \
     /var/lib/grayhaven/timetracker/rekey-rollback.XXXXXXXX)"
   sudo cp -a \
     /var/lib/grayhaven/timetracker/data/timetracker.sqlite3 \
     /var/lib/grayhaven/timetracker/secrets/sqlcipher_passphrase \
     "$ROLLBACK_DIR/"
   sudo find /var/lib/grayhaven/timetracker/data \
     -maxdepth 1 \
     -type f \
     \( -name 'timetracker.sqlite3-wal' \
        -o -name 'timetracker.sqlite3-shm' \) \
     -exec cp -a -t "$ROLLBACK_DIR" -- {} +
   printf 'Rollback directory: %s\n' "$ROLLBACK_DIR"
   ```

6. Rekey the database with the same immutable image recorded in step 4.

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

7. Verify the rekeyed database with the proposed passphrase.

   ```bash
   sudo podman run --rm \
     --user 777:777 \
     --read-only \
     --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
     --cap-drop all \
     --security-opt no-new-privileges \
     --volume /var/lib/grayhaven/timetracker/data:/app/data:ro,Z \
     --volume /var/lib/grayhaven/timetracker/secrets:/run/secrets:ro,Z \
     <approved-image>@sha256:<digest> \
     python scripts/database_maintenance.py verify \
     /app/data/timetracker.sqlite3 \
     /run/secrets/sqlcipher_passphrase.new
   ```

8. Replace the deployed passphrase and restore its managed metadata.

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

9. Update the encrypted configuration source to the same passphrase before
   another convergence can run.

10. Start the service and verify health, login, writes, reports, and the
    running image digest.

    ```bash
    sudo systemctl start grayhaven-timetracker.service
    sudo systemctl is-active --quiet grayhaven-timetracker.service
    sudo podman container inspect \
      --format '{{.ImageName}} {{.ImageDigest}}' \
      grayhaven-timetracker
    ```

If rekeying fails, keep the service stopped. Restore the database, sidecars,
and passphrase from the rollback directory, restore their ownership, modes,
and SELinux contexts, and start the service only after the database and active
passphrase are known to match.

[Back to top](#operations)

## Provision and Recover Users

The bootstrap-user manifest is used only when the user table is empty. Each
bootstrap account must change its initial password at first sign-in. The
manifest is not an account-reconciliation mechanism after the first startup.

To create an account after initial provisioning:

1. Sign in as an administrator.
2. Open **Users**.
3. Select **Add User**.
4. Enter the user's name, email address, role, and enabled state.
5. Save the account and securely deliver the one-time password.

To reset a user's password:

1. Sign in as an administrator.
2. Open **Users** and select the affected account.
3. Select **Reset Password**.
4. Complete password and TOTP reauthentication when prompted.
5. Securely deliver the displayed temporary password. It is shown only once.

To recover an account whose user also lost TOTP access:

1. Sign in as an administrator.
2. Open **Users** and select the affected account.
3. Disable the existing TOTP enrollment after completing reauthentication.
4. Have the user sign in with the temporary password, replace it, and enroll
   TOTP again.

Deliver passwords and TOTP provisioning information through separate approved
channels. The application has no email recovery flow.

[Back to top](#operations)

## Manage and Recover Passkeys

Passkeys are optional. Password and TOTP authentication remain available as a
fallback and cannot be disabled.

To register a passkey:

1. Sign in and open **Profile**.
2. Select **Manage Passkeys**.
3. Reauthenticate with the current password and TOTP code, or use an existing
   passkey.
4. Enter a name that identifies the device or credential provider.
5. Select **Add Passkey** and complete the browser or operating-system prompt.
6. Confirm that the named passkey appears under **Registered Passkeys**.

To remove one of your passkeys:

1. Open **Profile** and select **Manage Passkeys**.
2. Reauthenticate when prompted.
3. Select **Remove** beside the intended passkey and confirm the action.
4. Confirm that the passkey no longer appears in the registered list.

If a browser starts a passkey prompt automatically during login or a
sensitive action, cancel the browser prompt itself; these flows do not provide
an in-page **Cancel Passkey** control. The password and TOTP form remains
available as a fallback. The explicit **Cancel Passkey** control applies to
passkey enrollment only.
If a passkey is lost, sign in with the account password and TOTP enrollment,
then remove the lost credential. If password or TOTP access is unavailable but
a registered passkey remains, use that passkey to sign in and authorize the
corresponding profile recovery action.

To remove every passkey from another user's account:

1. Sign in as an administrator and open **Users**.
2. Select **Wipe All Passkeys** for the affected account.
3. Reauthenticate with password and TOTP or a passkey.
4. Confirm the destructive action.
5. Verify that the account reports **Not Configured** under **Passkeys**.

Wiping all passkeys invalidates every existing session for the affected user.
If the user has lost all authentication factors, reset the password, disable
TOTP, and wipe the passkeys through the separate administrator controls, then
deliver the temporary password through the approved recovery channel.

[Back to top](#operations)

## Correct Contract and Billing Records

To make a correction to completed time:

1. Sign in as an administrator.
2. Open **Sessions** and locate the affected session.
3. If the session is invoiced, paid, or disbursed, move it backward through
   the billing workflow until it is **Pending Invoice**.
4. Edit or move the pending session.
5. Move the corrected session forward through each billing stage again and
   enter the accurate invoice, payment, and disbursement metadata.
6. Review the audit log and confirm that each reversal, correction, and
   forward transition was recorded.

Archiving a contract stops its active timers and removes it from normal
selection and client reports. Activating the contract restores it. Deleted
clients, contracts, tasks, and subtasks are soft-deleted: they remain in the
database with their original identifiers but are hidden from normal workflows.

[Back to top](#operations)

## Manage Shared Client Reports

To enable a client's shared report:

1. Sign in as an administrator and open the client.
2. Generate a report password.
3. Record the password when it is displayed; it cannot be recovered later.
4. Send the permanent report URL and password through separate approved
   channels.

To revoke existing shared-report sessions, rotate the report password from the
client page. The report displays eligible live work. Invoiced, paid,
disbursed, and archived-contract time is excluded.

[Back to top](#operations)

## Change the Timezone

Ansible manages the host timezone and the Time Tracker container's `TZ`
setting from one configuration value. Do not change either value directly on
the managed host.

Follow the authoritative
[managed timezone procedure](https://github.com/dean1012/grayhaven-config-ansible/blob/main/docs/operations.md#changing-the-managed-timezone)
in the `grayhaven-config-ansible` repository. After convergence, verify a
representative time entry and report in the application. Timestamps remain
stored in UTC; changing the managed timezone changes display and entry
interpretation without rewriting stored timestamps.

[Back to top](#operations)

## Review Logs

1. Review the current systemd service state and recent container logs.

   ```bash
   sudo systemctl status grayhaven-timetracker.service --no-pager
   sudo journalctl \
     -u grayhaven-timetracker.service \
     --since today \
     --no-pager
   ```

2. Follow new service log entries during a controlled reproduction.

   ```bash
   sudo journalctl -u grayhaven-timetracker.service -f
   ```

3. Review reverse-proxy errors for the application.

   ```bash
   sudo tail -n 200 /var/log/nginx/timetracker.error.log
   ```

The application writes structured JSON to standard error. Authentication and
state-change events omit passwords, TOTP values, and report tokens. The
encrypted database contains the append-only application audit log available to
administrators. Persistent-volume growth must be monitored because audit
history is intentionally retained.

[Back to top](#operations)
