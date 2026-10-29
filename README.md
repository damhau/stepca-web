# Step CA Admin

A web-based dashboard for managing [Step CA](https://smallstep.com/docs/step-ca) – the open-source certificate authority. A React frontend over a Flask JSON API, it lets you browse ACME objects and X.509 certificates, sign and revoke certificates, and manage provisioners and admins.

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
  - All, valid, expiring (7, 30 or 90 days), expired and revoked certificates, filtered, sorted and paged by the server, with each certificate's lifetime drawn to scale. Certificates issued for 30 days or less (step-ca's default is 24 hours) are short-lived and never counted as expiring: they are meant to renew themselves.
  - A page per certificate: details, extensions, revocation status and reason; PEM, chain and DER downloads.
  - Sign a CSR (pasted or uploaded, previewed, with a chosen validity) with a JWK provisioner; revoke with an RFC 5280 reason.
- **ACME** (read-only): accounts, orders, certificates, authorizations and challenges, and the drill-down from an account to its orders, from an order to its authorizations, challenges and certificate.
- **Provisioners**: list, add (JWK, ACME), edit (durations, renewal, ACME options) and delete.
- **Admins**: list, add, change type and delete (when the app's CA identity is a super admin).
- **CA status**: health, version, root and intermediate certificates with their expiry, the CRL.
- **Dashboard**: the renewals due in the next 13 weeks, the inventory by status, certificates per provisioner, ACME orders by status.
- **Search** across certificates (serial in decimal or hex, subject, DNS name), ACME accounts and orders, provisioners and admins; **CSV export** of any list, every matching row.
- **Roles and audit log**: viewer, operator and admin roles; every change and sign-in is recorded.
- **Systemd service control** (optional, off by default): start, stop or restart step-ca.

Not supported: SSH certificates, ACME EAB keys (open-source step-ca can't create them), policies and webhooks.

## Project Structure

```
stepca-web/
├── app/
│   ├── __init__.py        # create_app(settings)
│   ├── settings.py        # typed settings: environment, then settings.json, then defaults
│   ├── api/               # the JSON API under /api/v1: pydantic models (schemas.py) and routes
│   ├── web.py             # serves the built frontend, and redirects the old pages' URLs
│   ├── services/          # what the API returns: certificates, inventory, acme, provisioners, dashboard, search, ca
│   ├── stepca/            # everything that knows step-ca
│   │   ├── client.py      # its API: Admin API (x5c token), sign and revoke (JWK token), public endpoints
│   │   ├── store.py       # its database: the key/value tables, read into records
│   │   └── records.py     # typed records: certificates, revocations, provisioners, admins, ACME objects
│   ├── auth/              # session check, roles, auth backend factory
│   ├── libs/              # auth backends (LDAP, local), audit log, certificate parsing, provisioner edits
│   └── models/            # SQLAlchemy tables: step-ca's (read-only) and the app's own
├── frontend/              # the React app (Vite, TypeScript); `npm run build` writes frontend/dist
│   ├── openapi.json       # the API's OpenAPI document, which src/api/schema.d.ts is generated from
│   └── src/
│       ├── routes/        # one file per page (TanStack Router)
│       ├── features/      # dialogs and forms: sign, revoke, provisioners, ACME tables
│       ├── components/    # the shell, tables, status badges, lifetime bars; ui/ holds the shadcn/ui components
│       └── api/           # the typed API client and session hooks
├── tests/                 # unit tests; tests/e2e/run.sh runs the API and browser tests against a real step-ca
├── docs/analysis-report.md
├── pyproject.toml / uv.lock
├── requirements.txt       # exported from uv.lock, for Dockerfile.pip
├── Dockerfile / Dockerfile.pip / docker-compose.yml
└── README.md
```

step-ca's database is only read, by `app/stepca/store.py`. Changes go through step-ca's API (`app/stepca/client.py`). Provisioners and admins are listed from the Admin API; the database only fills in what the API leaves out (provisioner ids, some admins' creation dates).

The certificate lists read an **inventory** in the app's own database (`app/services/inventory.py`): step-ca's certificates and revocations, parsed once. Neither ever changes once step-ca has written it, so keeping it current only means adding the new rows; each read checks for them at most every `INVENTORY_REFRESH_SECONDS` (5). It is built in the background at startup.

### Pages and API

The frontend's pages are `/`, `/certificates` (`?status=valid|expiring|expired|revoked`), `/certificates/<serial>`, `/acme/accounts[/<id>]`, `/acme/orders[/<id>]`, `/acme/authorizations`, `/acme/challenges`, `/acme/certificates`, `/ca`, `/provisioners[/<name>]`, `/admins`, `/settings`, `/audit`, `/search?q=` and `/service`. The old pages' URLs (`/x509/cert/<serial>`, `/step/provisioners`, ...) redirect to them.

Everything the frontend shows comes from the JSON API under `/api/v1`, documented by `frontend/openapi.json` (regenerate it with `uv run python -m app.api.openapi`):

- `GET/POST/DELETE /api/v1/session` – who is signed in and the CSRF token; sign in; sign out
- `GET /api/v1/certificates` – filtered (`status`, `days`, `q`, `provisioner`), sorted (`sort`, `order`) and paged (`page`, `per_page`); `format=csv` returns every matching row as a file. The ACME lists and the audit log take the same `q`, `page`, `per_page` and `format`
- `GET /api/v1/certificates/<serial>`, `/download?format=pem|chain|der`; `POST /api/v1/certificates` (sign a CSR), `/<serial>/revoke` (operator)
- `GET /api/v1/acme/{accounts,orders,authorizations,challenges,certificates}`, `/acme/accounts/<id>`, `/acme/orders/<id>`
- `GET/POST/PUT/DELETE /api/v1/provisioners[/<name>]`, `GET/POST/PATCH/DELETE /api/v1/admins[/<id>]` (changes: admin)
- `GET /api/v1/ca`, `/ca/roots.pem`, `/ca/intermediates.pem`, `/ca/crl?format=der|pem`
- `GET /api/v1/dashboard`, `/search?q=`, `/settings` and `/audit` (admin), `POST /api/v1/service` (admin, if enabled)

Every API route needs a session except `/api/v1/session`; writes need the session's CSRF token in an `X-CSRFToken` header, and a role (see [Roles](#roles)). Errors are `{"error": "..."}`. Scripts can use it the same way: `GET /api/v1/session` for a token, `POST` it with the credentials, then send the new token with each write.


## Frontend

- **Built with** Vite, React, TypeScript, Tailwind CSS and [shadcn/ui](https://ui.shadcn.com) components (Radix), TanStack Router, Query and Table. The API types are generated from `frontend/openapi.json`, so the frontend stops compiling when it no longer matches the API.
- **Served by Flask** from `frontend/dist` (`FRONTEND_DIR`), with the same strict Content-Security-Policy as the API: only the app's own scripts and styles, plus a per-response nonce for the two style elements its dialogs and selects add. No CDN.
- **Light and dark themes** (or the system's), and layouts for phones.
- **Lists** keep their filters, sort and page in the URL, so they can be bookmarked and shared.
- **`/`** focuses the search box from anywhere.


## Requirements

- Python 3.12+ and [uv](https://docs.astral.sh/uv/), and Node.js 22 to build the frontend (or Docker, see below)
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

   Then build the frontend:

   ```bash
   cd frontend && npm ci && npm run build && cd ..
   ```

3. **Create a read-only database role** for the app (see [Database Connection](#database-connection)).

4. **Give the app its own identity on the CA** (see [CA identity](#ca-identity)).

5. **Configure the database and CA connection**

   - Set the environment variables listed in `.env.example` (or put the same keys in `settings.json` in the working directory).
   - Set your PostgreSQL host, user, password, database, and port, and `SECRET_KEY`.
   - Set your Step CA URL and root fingerprint.
   - The **Settings** page shows the settings in effect (read-only, secrets hidden).

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

- The app's own data (the audit log, the certificate inventory, and certificates signed from the UI with their CSR) lives in a SQLite file, `stepca-web.db`, in the data directory (`DATA_DIR`, `/data` in the image). Override it with `APP_DATABASE_URI`.
- Connection parameters are set with environment variables or `settings.json` (in the data directory). Environment variables win.
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

   This builds `Dockerfile`, which builds the frontend with Node and installs the Python dependencies with uv. To use plain pip instead, set `DOCKERFILE=Dockerfile.pip` in `.env`. The build needs Docker Hub, PyPI and the npm registry.

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
- **Revocations** are made with the app's provisioner, so a revoked certificate's page shows `stepca-web` as the provisioner it was revoked through.
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
- Every change (sign, revoke, provisioner and admin changes, service actions) and every login is recorded in the audit log (**System > Audit log**, admins only) and printed to stdout.

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
- **`ldap://` without StartTLS sends passwords in cleartext.** It still works, but the app logs a warning at startup and the Settings page shows one.
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
- **Revocations made before the fix** revoked the wrong serial. The Revoked tab of the certificate list names the certificates that are still valid: revoke them again from their page.
- **Service control** is off unless `SERVICE_CONTROL_ENABLED=true`.
- **Data directory:** the app's files (`settings.json`, `admin.crt`, `admin.key`, `ca_root.crt`, `stepca-web.db`, `jwk_key.json`, `local_users.json`) are in `DATA_DIR`: `/data` in the image, as before; the working directory otherwise.
- **JSON API:** `/api/x509/*` and `/api/acme/*` return the app's records (`serial`, `subject`, `not_after` in ISO 8601, ...) instead of step-ca's raw rows.

## Upgrading to the React frontend

- **The old JSON API is gone:** `/api/x509/*` and `/api/acme/*` are replaced by `/api/v1` (see [Pages and API](#pages-and-api)), whose lists are paged: pass `per_page` (up to 500) and `page`, or `format=csv` for every row.
- **URLs changed;** the old pages' URLs redirect to the new ones.
- **Building from source** needs Node.js 22 for the frontend (`cd frontend && npm ci && npm run build`). The Docker images do it themselves, and the image build now also downloads from the npm registry.
- **Health check:** the images check `/healthz` instead of the sign-in page. Point your own monitoring there too.
- **Expiring certificates:** certificates issued for 30 days or less no longer count as expiring, on the dashboard or in the lists.
- **Provisioners:** the "Issues X.509 certificates" box is gone: step-ca ignores it (it issues X.509 certificates whatever its value).


## Development

- Install everything, including the test tools: `uv sync`, and `npm ci` in `frontend/`.
- **Backend:** lint and type-check with `uv run ruff check .` and `uv run mypy`; unit tests with `uv run pytest`. They use in-memory SQLite with the same table layout as step-ca, and a fake CA client; each test builds its own settings (`tests/conftest.py`).
- **Frontend:** `npm run dev` in `frontend/` serves it with hot reload on <http://localhost:5173> and forwards `/api` to the Flask app on port 5000 (`API_URL` to change it), started with `AUTH_BACKEND=local uv run python run.py`. `npm run lint`, `npm run format`, `npm run typecheck` and `npm test` (Vitest) check it.
- **API changes:** after changing `app/api/`, run `uv run python -m app.api.openapi` and `npm run api:gen` in `frontend/`: the frontend then type-checks against the new API. CI checks that both files are current.
- **End-to-end tests:** `tests/e2e/run.sh` starts a real step-ca on PostgreSQL and an OpenLDAP server, gets a certificate over ACME, runs the app on a read-only role, and tests the API (signing, revoking down to the CRL, provisioner editing, the ACME drill-down, CSRF, the inventory) and the frontend in headless Chromium (signing in, every page without CSP or script errors, signing and revoking through the dialogs). Needs Docker, and the browser once: `uv run playwright install --only-shell chromium`. `KEEP=1` leaves the stack running on <http://127.0.0.1:15000>; `DOCKERFILE=Dockerfile.pip` tests the pip image; `E2E_IDENTITY=super` uses the legacy `jwk_key.json` setup.
- After changing dependencies in `pyproject.toml`, run `uv lock` and `uv export --frozen --no-dev --no-emit-project -o requirements.txt`. CI checks both are in sync. Frontend dependencies are in `frontend/package-lock.json`; Dependabot proposes their updates weekly.
- The Content-Security-Policy refuses inline scripts and styles: keep styles in Tailwind classes or React's `style` prop, and avoid libraries that add `<style>` elements (most toast libraries do; the app has its own toaster).


## To Do / Ideas

- [ ] SSH certificates (inventory and revocation)
- [ ] Expiry notifications
- [ ] Bulk certificate operations


## Contact

Damien Hauser  
damien@dhconsulting.ch


**References:**
- [Step CA Documentation](https://smallstep.com/docs/step-ca)
- [Step CA GitHub](https://github.com/smallstep/certificates)


