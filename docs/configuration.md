# Configuration

[Return to README](../README.md)

This document defines the runtime interface expected by the
Grayhaven Systems LLC Time Tracker. Deployment automation should provide these
values and files; it should not encode private environment data in this
repository.

## Table of Contents

- [Runtime Settings](#runtime-settings)
- [Secrets](#secrets)
- [Bootstrap Users](#bootstrap-users)
- [Branding](#branding)
- [Public Image](#public-image)
- [Public Deployment](#public-deployment)
- [Local Compose](#local-compose)

## Runtime Settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `APP_VERSION` | `unversioned` | Version displayed by the application. |
| `BRANDING_PATH` | `/app/branding` | Required runtime branding directory. |
| `CONTACT_URL` | Grayhaven Systems LLC URL | Shared-report link. |
| `DATABASE_PATH` | `/app/data/timetracker.sqlite3` | SQLCipher database path. |
| `PUBLIC_BASE_URL` | unset | Canonical external HTTPS origin. |
| `SESSION_COOKIE_SECURE` | `false` | Restricts session cookies to HTTPS. |
| `SKIP_BOOTSTRAP` | `false` | Skips initial user provisioning. |
| `TRUSTED_HOSTS` | `localhost,127.0.0.1` | Browser Host allowlist. |
| `TRUSTED_PROXY_COUNT` | `0` | Number of trusted reverse proxies. |
| `TZ` | `America/Chicago` | IANA timezone used for display and entry. |
| `WEBAUTHN_ORIGIN` | required | Trusted WebAuthn ceremony origin. |
| `WEBAUTHN_RP_ID` | required | Hostname-only WebAuthn RP identifier. |

`PUBLIC_BASE_URL`, when set, must be an HTTPS origin whose hostname is allowed
by `TRUSTED_HOSTS`. It also requires `SESSION_COOKIE_SECURE=true`.

`WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` are independent trusted inputs. They are
never derived from `Host`, `X-Forwarded-Host`, or another request header. The RP
ID must be a lowercase hostname without a scheme, port, or path, and the
origin's hostname must match it exactly. Public deployments require HTTPS on
the default port. The supported local pair is exactly `localhost` and
`http://localhost:8000`; an IP address is not interchangeable with localhost.
Changing the RP ID makes credentials registered for the former RP unusable and
is an explicit compatibility event.

[Back to top](#configuration)

## Secrets

The following settings are required:

- `SECRET_KEY` or `SECRET_KEY_FILE`: Flask signing key of at least 32
  characters.
- `SQLCIPHER_PASSPHRASE` or `SQLCIPHER_PASSPHRASE_FILE`: SQLCipher passphrase
  of at least 32 characters.
- `BOOTSTRAP_USERS` or `BOOTSTRAP_USERS_FILE`: initial account manifest, unless
  `SKIP_BOOTSTRAP=true`.

Use file-backed values in managed environments. Secret files must be readable
only by the runtime identity and must not be included in the image, repository,
logs, or backups stored without equivalent protection. Do not set both the
direct and file-backed form of the same setting.

[Back to top](#configuration)

## Bootstrap Users

Bootstrap provisioning runs only when the user table is empty. The manifest is
a JSON array with at least one enabled administrator. Each entry supports:

- `email`, `first_name`, `last_name`, `password_hash`, and `role` as required
  fields.
- `role` set to `admin` or `user`.
- Optional `enabled`, defaulting to `true`.
- Optional `totp_secret` containing a valid Base32 secret or `null`.

Password values must be Argon2id hashes with the security parameters enforced
by the application. Generate the manifest through deployment automation; do
not store real or example credentials in Git. The structural sample under
`examples/` contains placeholders only.

Every bootstrap-created account must replace its initial password at first
sign-in. A preconfigured TOTP enrollment remains active during that password
change.

After initial provisioning, manage accounts through the application. Retaining
the manifest does not overwrite existing accounts.

[Back to top](#configuration)

## Branding

The runtime branding directory must contain:

```text
grayhaven-logo-wordmark-dark.svg
favicon.ico
favicon-16.png
favicon-32.png
apple-touch-icon.png
fonts/inter-400.ttf
fonts/inter-500.ttf
fonts/inter-600.ttf
fonts/inter-700.ttf
```

These assets are mounted at runtime and intentionally excluded from the public
application source. External adopters must supply branding they are authorized
to use and may need to adjust templates and styling for a different identity.

[Back to top](#configuration)

## Public Image

The application image is intentionally unbranded. `.dockerignore` excludes the
local `branding/` directory, and the Dockerfile creates an empty
`/app/branding` mount point rather than copying private assets. This allows the
MIT-licensed application image and proprietary Grayhaven Systems LLC identity
files to be distributed under separate terms.

Deployment automation installs the approved branding bundle on the target host
and mounts it read-only at `/app/branding`. The application validates the
required files at startup and fails closed when they are absent. Do not publish
an environment-specific branded derivative to the public image registry.

[Back to top](#configuration)

## Public Deployment

The application expects a trusted reverse proxy to terminate TLS. A managed
deployment must set:

- `PUBLIC_BASE_URL` to the canonical HTTPS origin.
- `SESSION_COOKIE_SECURE=true`.
- `TRUSTED_HOSTS` to the exact public hostnames.
- `TRUSTED_PROXY_COUNT` to the number of controlled proxy hops.
- `WEBAUTHN_RP_ID` to the canonical Time Tracker hostname.
- `WEBAUTHN_ORIGIN` to the exact canonical HTTPS origin.

For example, a deployment using `timetracker.example.com` as its canonical
hostname must use `timetracker.example.com` as the RP ID and
`https://timetracker.example.com` as the origin. Deployment automation should
derive both values from the same trusted canonical hostname.

Do not expose Gunicorn directly to an untrusted network. Proxy headers are
accepted only to the configured hop count, so that value must match the real
network path.

[Back to top](#configuration)

## Local Compose

`compose.yml` binds the application to `127.0.0.1:8000`, mounts `data/` as the
persistent database directory, and mounts `branding/` and `secrets/` read-only.
It also drops Linux capabilities, uses a read-only root filesystem, limits
processes, and provides a `/health` check.

The local definition defaults secure cookies off because it serves plain HTTP
on loopback. Do not carry that value into an HTTPS deployment.
It explicitly supplies RP ID `localhost` and origin
`http://localhost:8000`; open that hostname rather than `127.0.0.1` when
testing passkeys.

[Back to top](#configuration)
