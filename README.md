# Step CA Admin

A web-based dashboard for managing [Step CA](https://smallstep.com/docs/step-ca) – the open-source certificate authority. Built with Flask and styled with AdminLTE, it lets you browse ACME objects and X.509 certificates, sign and revoke certificates, and manage provisioners and admins.

## What is Step CA?

[Step CA](https://smallstep.com/docs/step-ca) is an open-source, private certificate authority (CA) designed for developers, DevOps, and security teams. It provides secure, automated certificate management for internal infrastructure, including:

- X.509 certificates for TLS/SSL
- SSH certificates for secure access
- ACME protocol support for automation

Step CA is highly configurable, supports multiple provisioner types (JWK, ACME, OIDC, etc.), and is production-ready for modern infrastructure.

**Official Documentation:**  
https://smallstep.com/docs/step-ca

**Important:**
- Step CA must be configured to use an external database such as PostgreSQL. See the [Step CA Database documentation](https://smallstep.com/docs/step-ca/db/) for setup instructions.
- Step CA must have [remote provisioner and admin management](https://smallstep.com/docs/step-ca/provisioners/) enabled (`step ca init --remote-management`, or `"enableAdmin": true` in the `authority` section of `ca.json`), so this UI can manage provisioners and admins through the Admin API.

## Features

- **X.509 certificates**
  - All, active, expiring (7, 30 or 90 days) and revoked certificates; search, sort and paging on every list.
  - A page per certificate: details, extensions, revocation status and reason; PEM, chain and DER downloads.
  - Sign a CSR with a JWK provisioner; revoke with an RFC 5280 reason.
- **ACME**: read-only lists of accounts, orders, certificates, authorizations and challenges.
- **Provisioners**: list, add (JWK, ACME), edit (durations, renewal, ACME options) and delete.
- **Admins**: list, add, change type and delete (when the app's CA identity is a super admin).
- **CA status**: health, version, root and intermediate certificates with their expiry, the CRL.
- **Dashboard**: active, expiring and revoked certificates, provisioners, charts.
- **Roles and audit log**: viewer, operator and admin roles; every change and sign-in is recorded.
- **Systemd service control** (optional, off by default): start, stop or restart step-ca.

Not supported: SSH certificates, ACME EAB keys (open-source step-ca can't create them), policies and webhooks.

## Project Structure

```
stepca-web/
├── app/
│   ├── blueprint/
│   │   ├── acme/
│   │   │   └── routes.py
│   │   ├── home/
│   │   │   └── routes.py
│   │   ├── step/
│   │   │   └── routes.py
│   │   ├── system/
│   │   │   └── routes.py
│   │   └── x509/
│   │       └── routes.py
│   ├── auth/              # login check, roles, auth backend factory
│   ├── libs/
│   │   ├── auth/          # LDAP and local auth backends
│   │   ├── audit.py       # audit log
│   │   ├── ca.py          # the shared CA client, CA status
│   │   ├── cert_utils.py
│   │   ├── db_acme.py     # read step-ca's tables
│   │   ├── db_step.py
│   │   ├── db_x509.py
│   │   ├── provisioners.py
│   │   └── stepapi.py     # step-ca API client
│   ├── templates/
│   │   └── ... (Jinja2 HTML templates)
│   └── static/
│       └── ... (CSS, JS, icons)
├── tests/                 # unit tests; tests/e2e/run.sh runs them against a real step-ca
├── docs/analysis-report.md
├── pyproject.toml / uv.lock
├── requirements.txt       # exported from uv.lock, for Dockerfile.pip
├── Dockerfile / Dockerfile.pip / docker-compose.yml
└── README.md
```

## Backend: Python API and Endpoints

### Blueprints and Routing

The backend is organized using Flask blueprints:

- **app/blueprint/acme/routes.py**: ACME account/order/cert/authz/challenge views
- **app/blueprint/x509/routes.py**: X.509 certificate management
- **app/blueprint/step/routes.py**: Provisioners, admins, CA status, service control
- **app/blueprint/system/routes.py**: Configuration (read-only) and audit log
- **app/blueprint/home/routes.py**: Dashboard and summary

### Key Python Functions

#### Database Access

- **db_acme.py**: Functions to fetch ACME accounts, orders, certs, authzs, challenges from PostgreSQL.
- **db_x509.py**: Functions to fetch X.509 certs, revoked certs, and related metadata.
- **db_step.py**: Functions to fetch provisioners and admins.

#### Step CA API Wrapper (`stepapi.py`)

- **StepCAClient**: Main class for interacting with Step CA's REST API.
  - `list_provisioners()`, `get_provisioner(name)`, `create_provisioner_jwk()`, `create_provisioner_acme()`, `update_provisioner()`, `delete_provisioner()`
  - `list_admins()`, `create_admin()`, `update_admin()`, `delete_admin()`
  - `sign()`, `revoke()`: Certificate signing and revocation
  - `health()`, `version()`, `roots()`, `intermediates()`, `crl()`: the CA's public endpoints
  - Internal helpers for JWT, JWK, and certificate handling

#### Certificate Utilities (`cert_utils.py`)

- `parse_cert()`, `parse_cert_from_bytes()`: Subject, issuer, validity, serial, key and DNS names of a PEM or DER certificate.
- `certificate_extensions()`: The extensions, readable.
- `issuing_provisioner()`: The step-ca provisioner that issued a certificate.
- `extract_sans_from_csr()`: Extract SANs from a CSR.

### Routes

Every route needs a session except `/auth/login`. Changes need a role (see [Roles](#roles)) and a CSRF token.

#### ACME

- `/acme/accounts`, `/acme/orders`, `/acme/certs`, `/acme/authzs`, `/acme/challenges` – lists
- `/api/acme/<kind>` – the same as JSON

#### X.509

- `/x509/all`, `/x509/active`, `/x509/revoked` – lists
- `/x509/expiring?days=7|30|90` – certificates expiring soon
- `/x509/cert/<serial>` – one certificate (decimal serial)
- `/x509/download/<serial>?format=pem|chain|der` – download a certificate
- `/x509/sign` (POST, operator) – sign a CSR
- `/x509/revoke` (POST, operator) – revoke a certificate
- `/api/x509/certs`, `/api/x509/certs/<serial>` – JSON

#### Step CA

- `/step/ca` – CA status; `/step/ca/roots.pem`, `/step/ca/intermediates.pem`, `/step/ca/crl` – downloads
- `/step/provisioners` – list; POST (admin) adds one
- `/step/provisioner/<name>/edit` (admin) – edit a provisioner
- `/step/provisioner/<name>/delete` (POST, admin) – delete a provisioner
- `/step/admins` – list; POST (admin) adds one
- `/step/admin/<id>/update`, `/step/admin/<id>/delete` (POST, admin) – change an admin's type, delete it
- `/step/service`, `/step/service/<action>` (POST) (admin, if enabled) – service control

#### System

- `/system/config` (admin) – the settings in effect, read-only
- `/system/audit` (admin) – the audit log

#### Home

- `/` – Dashboard overview


## Frontend: GUI Overview

The GUI is built with Flask/Jinja2 templates and styled using AdminLTE and Bootstrap.

- **Dashboard**: KPIs for active, expiring and revoked certificates and provisioners.
- **ACME Management**: Tables for accounts, orders, certs, authorizations, and challenges.
- **X.509 Management**: Tables for all, active, expiring and revoked certificates, and a page per certificate with its extensions, downloads (PEM, chain, DER) and revoke (with a reason).
- **Every list** can be searched, sorted by any column and paged (50 rows per page), without any third-party script.
- **Provisioner Management**: Table of provisioners with view, add, edit and delete.
- **CA Status**: Health, version, roots, intermediates and CRL of the CA.
- **Admin Management**: Table of admins with add, type change and delete (when the app's CA identity is a super admin).
- **Configuration**: Read-only view of the settings in effect.
- **Audit Log**: Who did what, for admins.
- **Service Control** (optional, `SERVICE_CONTROL_ENABLED=true`): Buttons to start/stop/restart Step CA via systemd.
- **Navigation**: Sidebar for quick access to all sections.


## Requirements

- Python 3.12+ and [uv](https://docs.astral.sh/uv/) (or Docker, see below)
- Linux with `systemd`, only for the optional service control page
- Step CA installed and configured
- step-ca with remote management enabled, its database on PostgreSQL (the app is tested with step-ca 0.30)
- A JWK provisioner and an admin for the app (see [CA identity](#ca-identity))


## Installation & Deployment

1. **Clone the repository**

   ```bash
   git clone https://github.com/damhau/stepca-web
   cd stepca-web
   ```

2. **Install the dependencies**

   ```bash
   uv sync --no-dev
   ```

   This installs the exact versions pinned in `uv.lock` into `.venv`. Without uv, `pip install --require-hashes -r requirements.txt` installs the same versions.

3. **Create a read-only database role** for the app (see [Database Connection](#database-connection)).

4. **Give the app its own identity on the CA** (see [CA identity](#ca-identity)).

5. **Configure the database and CA connection**

   - Set the environment variables listed in `.env.example` (or put the same keys in `settings.json` in the working directory).
   - Set your PostgreSQL host, user, password, database, and port, and `SECRET_KEY`.
   - Set your Step CA URL and root fingerprint.
   - The `/system/config` page shows the settings in effect (read-only, secrets hidden).

6. **Run the app**

   ```bash
   uv run flask --app app run
   ```

   Then open your browser at: [http://localhost:5000](http://localhost:5000)

### Database Connection

- The app expects a PostgreSQL database with Step CA tables (`x509_certs`, `acme_accounts`, `provisioners`, etc.).
- The app only **reads** step-ca's database, so give it a read-only role. Changes to the CA go through the step-ca API. Run this as a PostgreSQL superuser, replacing `step-ca` with the role step-ca itself uses:

  ```sql
  CREATE ROLE stepca_web LOGIN PASSWORD 'change-me';
  GRANT CONNECT ON DATABASE step_ca_db TO stepca_web;
  GRANT USAGE ON SCHEMA public TO stepca_web;
  GRANT SELECT ON ALL TABLES IN SCHEMA public TO stepca_web;
  -- tables step-ca creates later (e.g. when ACME is first used)
  ALTER DEFAULT PRIVILEGES FOR ROLE "step-ca" IN SCHEMA public GRANT SELECT ON TABLES TO stepca_web;
  ```

- The app's own data (certificates signed from the UI, with their CSR) lives in a SQLite file, `stepca-web.db`, in the working directory. Override it with `APP_DATABASE_URI`.
- Connection parameters are set with environment variables or `settings.json`.
- Example config:

  ```json
  {
    "database": {
      "host": "localhost",
      "user": "step-ca",
      "password": "step-ca",
      "name": "step_ca_db",
      "port": 5432
    },
    "ca": {
      "url": "https://ca.example.com",
      "fingerprint": "YOUR_CA_FINGERPRINT"
    }
  }
  ```


## Docker Deployment

The image runs the app with gunicorn as a non-root user. All configuration comes from environment variables (`settings.json` is optional).

1. **Create the app's identity on the CA** (see [CA identity](#ca-identity)) and put its provisioner password in `ca_admin_password.txt` next to `docker-compose.yml`. It is mounted as a Docker secret and must be readable by uid 1000 (e.g. `chmod 640` and group 1000, or `chmod 644` on a host only you use).

2. **Create the `.env` file**

   ```bash
   cp .env.example .env
   ```

   Fill in `SECRET_KEY`, the step-ca database credentials and the CA URL. Env var names follow the `settings.json` keys: `database.host` → `DATABASE_HOST`, `ca.url` → `CA_URL`, and so on.

3. **Start it**

   ```bash
   docker compose up -d --build
   ```

   This builds `Dockerfile`, which installs the dependencies with uv. To use plain pip instead, set `DOCKERFILE=Dockerfile.pip` in `.env`.

   The UI listens on `127.0.0.1:5000` by default. Put a TLS reverse proxy in front of it, or set `STEPCA_WEB_BIND=0.0.0.0` in `.env` to expose it directly.

Notes:

- The app verifies the CA's TLS certificate. On first use it downloads the root from `CA_URL/root/<CA_FINGERPRINT>`, checks its SHA-256 against `CA_FINGERPRINT`, and saves it as `ca_root.crt`. You can provide the root yourself with `CA_ROOT`. The host in `CA_URL` must be one of the CA's DNS names.
- To reach a step-ca or PostgreSQL running on the Docker host, use `host.docker.internal` as the hostname. PostgreSQL must listen on the Docker bridge interface and allow the connection in `pg_hba.conf`.
- `admin.crt`, `admin.key`, `ca_root.crt` and the app's SQLite database `stepca-web.db` live in the `stepca-web-data` volume.
- The Step CA service control page (`sudo` + systemd) does not work inside the container.

### Behind a reverse proxy

Serve the UI over HTTPS through a reverse proxy, and set:

```bash
SESSION_COOKIE_SECURE=true   # the session cookie is only sent over HTTPS, and HSTS is on
TRUSTED_PROXIES=1            # the number of proxies in front of the app
```

With `TRUSTED_PROXIES`, the app takes the client address from `X-Forwarded-For`, so the sign-in rate limit (`LOGIN_RATE_LIMIT`, 10 failed sign-ins per minute and 50 per hour per address) counts each client separately. Leave it at 0 without a proxy: clients could otherwise send any address. The app also sends a Content-Security-Policy that only allows its own scripts, and refuses to be framed.


## CA identity

The app manages provisioners and admins through step-ca's Admin API, and revokes certificates, as an admin of the CA. Give it its own admin rather than the super admin `step` you use yourself:

```bash
# A JWK provisioner and an ADMIN for the app (asks for the "Admin JWK" password)
step ca provisioner add stepca-web --type JWK --create --password-file stepca-web.pass \
  --admin-subject step --admin-provisioner "Admin JWK"
step ca admin add stepca-web stepca-web \
  --admin-subject step --admin-provisioner "Admin JWK"
```

Then configure the app:

```bash
CA_ADMIN_PROVISIONER_NAME=stepca-web
CA_ADMIN_SUBJECT=stepca-web
CA_ADMIN_PASSWORD_FILE=/run/secrets/ca_admin_password   # contents of stepca-web.pass
```

- **The key never touches the disk.** On first use the app fetches the provisioner's encrypted key from the CA and decrypts it in memory with the password from `CA_ADMIN_PASSWORD_FILE`. Revoking needs no passphrase.
- **Least privilege.** An ADMIN can manage provisioners but not admins: the Admins page becomes read-only, and you manage admins with `step ca admin`. Note that an ADMIN can still create provisioners, so it can still issue certificates: protect the app accordingly.
- **Switching identity** is safe: the app re-issues its admin certificate (`admin.crt` in the working directory) when it doesn't match `CA_ADMIN_SUBJECT` and `CA_ADMIN_PROVISIONER_NAME`.
- **Revocations** are made with the app's provisioner, so the Revoked list shows `stepca-web` under "Revoked via".
- **Legacy setup:** without `CA_ADMIN_PASSWORD_FILE`, the app reads the provisioner's decrypted key from `jwk_key.json` in the working directory:

  ```bash
  step ca provisioner list \
    | jq -r '.[] | select(.name == "Admin JWK") | .encryptedKey' \
    | step crypto jwe decrypt \
    | jq > jwk_key.json
  ```

## Roles

| Role | Can |
|---|---|
| viewer | See every list, certificate and dashboard |
| operator | Also sign CSRs and revoke certificates |
| admin | Also manage provisioners and admins, see the configuration and the audit log, control the service |

- **LDAP:** set `ROLE_ADMIN_GROUP`, `ROLE_OPERATOR_GROUP` and `ROLE_VIEWER_GROUP` to group DNs. The highest matching group wins. Users in none of them get `DEFAULT_ROLE` (`viewer` by default; `none` refuses them).
- **Local users:** set `"role"` for each user in `local_users.json`.
- Every change (sign, revoke, provisioner and admin changes, service actions) and every login is recorded in the audit log (**System > Audit Log**, admins only) and printed to stdout.

To keep the behaviour from before roles existed (every LDAP user can do everything), set `DEFAULT_ROLE=admin`.

## Authentication

Two auth backends are available, selected with the `AUTH_BACKEND` environment variable: `ldap` (default) and `local`. The factory dispatching the choice lives in `app/auth/factory.py`.

### LDAP setup

```bash
AUTH_BACKEND=ldap
LDAP_URL=ldaps://dc.example.com          # or ldap:// with LDAP_START_TLS=true
LDAP_CA_FILE=/data/ldap-ca.crt           # CA of the LDAP server's certificate; system CAs if unset
LDAP_DOMAIN=example.com                  # Active Directory: users bind as <username>@LDAP_DOMAIN
# LDAP_BIND_DN=uid={username},ou=people,dc=example,dc=com   # other servers: bind with a DN
LDAP_BASE_DN=dc=example,dc=com
LDAP_USER_SEARCH_FILTER=(sAMAccountName={username})         # (uid={username}) by default
```

- **The server certificate is always verified** for `ldaps://` and StartTLS: against `LDAP_CA_FILE`, or the system CAs. A server whose certificate doesn't verify, or doesn't name the host in `LDAP_URL`, refuses every login, and the reason is logged.
- **`ldap://` without StartTLS sends passwords in cleartext.** It still works, but the app logs a warning at startup and the Configuration page shows one.
- Groups come from the user's `memberOf` attribute (on OpenLDAP, enable the memberof overlay) and are mapped to roles (see [Roles](#roles)). `LDAP_REQUIRED_GROUP_DN` optionally restricts login to one group.

### Local auth setup

Use this when you want a self-contained login without an external identity provider. Users are read from `local_users.json` in the working directory (override the path with `LOCAL_USERS_FILE`). The file is git-ignored: never commit it.

1. **Generate a password hash**

   Werkzeug ships with Flask, so no extra install is needed:

   ```bash
   uv run python -c "from werkzeug.security import generate_password_hash; import getpass; print(generate_password_hash(getpass.getpass('Password: ')))"
   ```

   The command prompts for a password (input is hidden) and prints a hash like `scrypt:32768:8:1$...`.

2. **Create `local_users.json`**

   Add your username and the hash from step 1:

   ```json
   {
     "admin": {
       "password_hash": "scrypt:32768:8:1$...PASTE_HERE...",
       "role": "admin"
     }
   }
   ```

   `role` is `viewer`, `operator` or `admin` (see [Roles](#roles)). Users without one get `DEFAULT_ROLE`.

   With Docker, uncomment the `local_users.json` volume in `docker-compose.yml`. The file must be readable by uid 1000.

3. **Select the local backend and run the app**

   ```bash
   AUTH_BACKEND=local uv run python run.py
   ```

   Then log in at [http://localhost:5000](http://localhost:5000) with the username and password you configured.


## Service control

The optional service page (`SERVICE_CONTROL_ENABLED=true`, admins only) runs `sudo /usr/local/bin/stepca_ctl.sh <start|stop|restart|status>`. It only works when the app runs on the CA's host, not in Docker. A script and a sudoers rule limited to it, for a `step-ca` systemd unit and an app running as `stepca-web`:

```bash
#!/bin/sh
# /usr/local/bin/stepca_ctl.sh, owned by root, mode 755
case "$1" in
  start|stop|restart) exec systemctl "$1" step-ca ;;
  status) exec systemctl status --no-pager step-ca ;;
  *) echo "usage: $0 start|stop|restart|status" >&2; exit 2 ;;
esac
```

```
# /etc/sudoers.d/stepca-web (edit with visudo -f)
stepca-web ALL=(root) NOPASSWD: /usr/local/bin/stepca_ctl.sh start, /usr/local/bin/stepca_ctl.sh stop, /usr/local/bin/stepca_ctl.sh restart, /usr/local/bin/stepca_ctl.sh status
```


## Upgrading from versions before October 2026

These changes need action:

- **Required settings:** the app refuses to start without `SECRET_KEY`, `CA_URL` and `DATABASE_HOST`. `CA_FINGERPRINT` (or `CA_ROOT`) is required to reach the CA, whose TLS certificate is now verified.
- **CA identity:** create the app's own provisioner and admin (see [CA identity](#ca-identity)) and put its password in `ca_admin_password.txt`, which `docker-compose.yml` mounts as a secret. `jwk_key.json` still works, but keeps a decrypted signing key on disk.
- **Roles:** LDAP users who match no role group get `DEFAULT_ROLE`, `viewer` by default. Set `ROLE_ADMIN_GROUP` (or `DEFAULT_ROLE=admin` for the old behaviour). Local users need a `role` in `local_users.json`.
- **LDAP:** `ldaps://` and StartTLS now verify the server certificate: set `LDAP_CA_FILE` if the system CAs don't know the one that issued it. `LDAP_REQUIRED_GROUP_DN` no longer defaults to `LDAP_BASE_DN`.
- **Database:** the app only reads step-ca's database. Give it a read-only role (see [Database Connection](#database-connection)). The `generated_certs` table it used to create in step-ca's database can be dropped.
- **Revocations made before the fix** revoked the wrong serial. The Revoked page marks them "Ineffective" and links to the certificate that is still valid: revoke it again from its page.
- **Service control** is off unless `SERVICE_CONTROL_ENABLED=true`.


## Development

- Install everything, including the test tools: `uv sync`.
- Lint: `uv run ruff check .`
- Unit tests: `uv run pytest`. They use in-memory SQLite with the same table layout as step-ca, and a fake CA client.
- End-to-end tests: `tests/e2e/run.sh` starts a real step-ca on PostgreSQL and an OpenLDAP server, runs the app on a read-only role, and tests signing, revoking (down to the CRL), provisioner editing, CSRF, pagination and LDAP over TLS against them. Needs Docker. `KEEP=1` leaves the stack running; `DOCKERFILE=Dockerfile.pip` tests the pip image; `E2E_IDENTITY=super` uses the legacy `jwk_key.json` setup.
- After changing dependencies in `pyproject.toml`, run `uv lock` and `uv export --frozen --no-dev --no-emit-project -o requirements.txt`. CI checks both are in sync.
- Use the built-in Flask dev server for local testing.
- For UI, modify `app/templates/` and `app/static/`.
- To add new pages, extend `layouts/base.html` and register routes in the appropriate blueprint. Page scripts go in `app/static/assets/js/`: the Content-Security-Policy blocks inline scripts and event handlers.
- Backend logic is in `app/libs/` and blueprints in `app/blueprint/`.


## To Do / Ideas

- [ ] SSH certificates (inventory and revocation)
- [ ] Server-side paging and a cache for CAs with tens of thousands of certificates
- [ ] Expiry notifications
- [ ] Bulk certificate operations


## Contact

Damien Hauser  
damien@dhconsulting.ch


**References:**
- [Step CA Documentation](https://smallstep.com/docs/step-ca)
- [Step CA GitHub](https://github.com/smallstep/certificates)


