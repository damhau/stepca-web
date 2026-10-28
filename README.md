# Step CA Admin

A web-based dashboard for managing [Step CA](https://smallstep.com/docs/step-ca) – the open-source certificate authority. Built with Flask and styled with AdminLTE, it provides an intuitive UI to manage ACME accounts, X.509 and SSH certificates, provisioners, and system services.

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
- You must also enable the [Remote Provisioner](https://smallstep.com/docs/step-ca/provisioners/#remote-provisioner) in your Step CA configuration to allow this admin UI to manage provisioners and admins remotely.

## Features

- **ACME Management**
  - List and manage ACME Accounts, Orders, Certificates, Authorizations, and Challenges.
- **X.509 Certificate Management**
  - View valid and revoked certificates with detailed info and linked provisioners.
- **SSH Certificate Management**
  - View all issued SSH certificates.
- **Provisioner Management**
  - List, add, and delete JWK/ACME provisioners.
- **Admin Users**
  - View and manage admin provisioners.
- **Expiry Monitoring**
  - Dashboard tile and a list of certificates expiring within 7, 30 or 90 days.
- **Roles and Audit Log**
  - Viewer, operator and admin roles; every change is recorded in an audit log.
- **Systemd Service Control** (optional, off by default)
  - Start, stop, or restart the Step CA systemd service (with limited permissions).
- **Dashboard Overview**
  - Visual KPIs: number of active certs, revoked certs, provisioners, etc.

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
│   ├── libs/
│   │   ├── cert_utils.py
│   │   ├── db_acme.py
│   │   ├── db_conn.py
│   │   ├── db_step.py
│   │   ├── db_x509.py
│   │   └── stepapi.py
│   ├── templates/
│   │   └── ... (Jinja2 HTML templates)
│   └── static/
│       └── ... (CSS, JS, icons)
├── tests/                 # unit tests; tests/e2e/run.sh runs them against a real step-ca
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
- **app/blueprint/step/routes.py**: Provisioner and admin management, Step CA service control
- **app/blueprint/system/routes.py**: App/system configuration
- **app/blueprint/home/routes.py**: Dashboard and summary

### Key Python Functions

#### Database Access

- **db_acme.py**: Functions to fetch ACME accounts, orders, certs, authzs, challenges from PostgreSQL.
- **db_x509.py**: Functions to fetch X.509 certs, revoked certs, and related metadata.
- **db_step.py**: Functions to fetch provisioners and admins.

#### Step CA API Wrapper (`stepapi.py`)

- **StepCAClient**: Main class for interacting with Step CA's REST API.
  - `list_provisioners()`, `get_provisioner(name)`, `create_provisioner_jwk()`, `create_provisioner_acme()`, `update_provisioner()`, `delete_provisioner()`
  - `list_admins()`, `create_admin()`, `delete_admin()`
  - `sign()`, `revoke()`: Certificate signing and revocation
  - Internal helpers for JWT, JWK, and certificate handling

#### Certificate Utilities (`cert_utils.py`)

- `parse_cert()`, `parse_cert_from_bytes()`: Parse and extract details from PEM/DER certificates.
- `decode_certificate()`: Extracts subject, issuer, validity, SANs, etc.
- `extract_sans_from_csr()`: Extract SANs from a CSR.

### API Endpoints

#### ACME

- `/acme/accounts` – List ACME accounts
- `/acme/orders` – List ACME orders
- `/acme/certs` – List ACME certificates
- `/acme/authzs` – List ACME authorizations
- `/acme/challenges` – List ACME challenges

#### X.509

- `/x509/all` – List all X.509 certificates
- `/x509/active` – List active X.509 certificates
- `/x509/revoked` – List revoked X.509 certificates
- `/x509/download/<serial>` – Download a certificate
- `/x509/sign` (POST) – Sign a new certificate (CSR)
- `/x509/revoke` (POST) – Revoke a certificate

#### Step CA Management

- `/step/provisioners` – List/add provisioners (GET/POST)
- `/step/provisioner/<name>/delete` – Delete a provisioner
- `/step/admins` – List/add admins (GET/POST)
- `/step/admin/<id>/delete` – Delete an admin
- `/step/service` – Service control UI
- `/step/service/<action>` (POST) – Start/stop/restart/status for Step CA systemd service

#### System

- `/system/config` – Edit application/database/CA config

#### Home

- `/` – Dashboard overview


## Frontend: GUI Overview

The GUI is built with Flask/Jinja2 templates and styled using AdminLTE and Bootstrap.

- **Dashboard**: KPIs for active, expiring and revoked certificates and provisioners.
- **ACME Management**: Tables for accounts, orders, certs, authorizations, and challenges.
- **X.509 Management**: Tables for all, active, expiring and revoked certificates, and a page per certificate with download and revoke (with a reason).
- **Provisioner Management**: Table of provisioners with view, add and delete.
- **Admin Management**: Table of admins with add, type change and delete (when the app's CA identity is a super admin).
- **Configuration**: Read-only view of the settings in effect.
- **Audit Log**: Who did what, for admins.
- **Service Control** (optional, `SERVICE_CONTROL_ENABLED=true`): Buttons to start/stop/restart Step CA via systemd.
- **Navigation**: Sidebar for quick access to all sections.


## Requirements

- Python 3.12+ and [uv](https://docs.astral.sh/uv/) (or Docker, see below)
- Linux with `systemd`, only for the optional service control page
- Step CA installed and configured
- PostgreSQL database with Step CA data
- A configured admin provisioner (JWK)


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
- `admin.crt`, `admin.key`, `ca_root.crt`, the app's SQLite database `stepca-web.db` and any `settings.json` saved from `/system/config` live in the `stepca-web-data` volume.
- The Step CA service control page (`sudo` + systemd) does not work inside the container.


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

The app supports several auth backends, selected via the `AUTH_BACKEND` environment variable (`config.py`): `ldap` (default), `radius`, `saml`, `oidc`, `local`. The factory dispatching the choice lives in `app/auth/factory.py`.

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


## Development

- Install everything, including the test tools: `uv sync`.
- Lint: `uv run ruff check .`
- Unit tests: `uv run pytest`. They use in-memory SQLite with the same table layout as step-ca, and a fake CA client.
- End-to-end tests: `tests/e2e/run.sh` starts a real step-ca on PostgreSQL, runs the app on a read-only role and tests signing, revoking, CSRF and pagination against it. Needs Docker. `KEEP=1` leaves the stack running; `DOCKERFILE=Dockerfile.pip` tests the pip image.
- After changing dependencies in `pyproject.toml`, run `uv lock` and `uv export --frozen --no-dev --no-emit-project -o requirements.txt`. CI checks both are in sync.
- Use the built-in Flask dev server for local testing.
- For UI, modify `app/templates/` and `app/static/`.
- To add new pages, extend `layout.html` and register routes in the appropriate blueprint.
- Backend logic is in `app/libs/` and blueprints in `app/blueprint/`.


## To Do / Ideas

- [ ] Add user authentication (basic auth or OAuth)
- [ ] Implement audit logging
- [ ] Add filtering and searching in tables
- [ ] Support bulk certificate operations
- [ ] UI for creating short-lived MTLS certs



## Contact

Damien Hauser  
damien@dhconsulting.ch


**References:**
- [Step CA Documentation](https://smallstep.com/docs/step-ca)
- [Step CA GitHub](https://github.com/smallstep/certificates)


