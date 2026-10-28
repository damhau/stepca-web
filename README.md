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
- **Step CA Config Editor**
  - Edit and validate the `ca.json` file with JSON syntax highlighting.
- **Systemd Service Control**
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
├── requirements.txt
├── README.md
└── jwk_key.json
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

- **Dashboard**: Shows KPIs for certificates, provisioners, and revoked certs.
- **ACME Management**: Tables for accounts, orders, certs, authorizations, and challenges.
- **X.509 Management**: Tables for all, active, and revoked certificates. Modal dialogs for certificate details and actions (sign, revoke, download).
- **Provisioner Management**: Table of provisioners with add/edit/delete modals.
- **Admin Management**: Table of admin users with add/edit/delete modals.
- **Config Editor**: JSON editor for `ca.json` with validation.
- **Service Control**: Buttons to start/stop/restart Step CA via systemd.
- **Navigation**: Sidebar for quick access to all sections.


## Requirements

- Python 3.9+
- Linux with `systemd` (for service management)
- Step CA installed and configured
- PostgreSQL database with Step CA data
- A configured admin provisioner (JWK)


## Installation & Deployment

1. **Clone the repository**

   ```bash
   git clone https://github.com/damhau/stepca-web
   cd stepca-web
   ```

2. **Create a virtual environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Generate the `jwk_key.json` file**

   This file is required for admin JWT authentication with Step CA.  
   Run the following command (replace `"Admin JWK"` with your provisioner name if different):

   ```bash
   step ca provisioner list \
     | jq -r '.[] | select(.name == "Admin JWK") | .encryptedKey' \
     | step crypto jwe decrypt \
     | jq > jwk_key.json
   ```

5. **Configure the database and CA connection**

   - Edit `app/settings.json` or use the `/system/config` page in the GUI.
   - Set your PostgreSQL host, user, password, database, and port.
   - Set your Step CA URL and fingerprint.

6. **Run the app**

   ```bash
   flask run
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
- Connection parameters are set in `settings.json` or via the `/system/config` page.
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

1. **Generate `jwk_key.json`** in the project root (see step 4 above). It is mounted read-only into the container and must be readable by uid 1000.

2. **Create the `.env` file**

   ```bash
   cp .env.example .env
   ```

   Fill in `SECRET_KEY`, the step-ca database credentials and the CA URL. Env var names follow the `settings.json` keys: `database.host` → `DATABASE_HOST`, `ca.url` → `CA_URL`, and so on.

3. **Start it**

   ```bash
   docker compose up -d --build
   ```

   The UI listens on `127.0.0.1:5000` by default. Put a TLS reverse proxy in front of it, or set `STEPCA_WEB_BIND=0.0.0.0` in `.env` to expose it directly.

Notes:

- The app verifies the CA's TLS certificate. On first use it downloads the root from `CA_URL/root/<CA_FINGERPRINT>`, checks its SHA-256 against `CA_FINGERPRINT`, and saves it as `ca_root.crt`. You can provide the root yourself with `CA_ROOT`. The host in `CA_URL` must be one of the CA's DNS names.
- To reach a step-ca or PostgreSQL running on the Docker host, use `host.docker.internal` as the hostname. PostgreSQL must listen on the Docker bridge interface and allow the connection in `pg_hba.conf`.
- `admin.crt`, `admin.key`, `ca_root.crt`, the app's SQLite database `stepca-web.db` and any `settings.json` saved from `/system/config` live in the `stepca-web-data` volume.
- The Step CA service control page (`sudo` + systemd) does not work inside the container.


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
       "attributes": {"role": "admin"}
     }
   }
   ```

   With Docker, uncomment the `local_users.json` volume in `docker-compose.yml`. The file must be readable by uid 1000.

3. **Select the local backend and run the app**

   ```bash
   AUTH_BACKEND=local uv run python run.py
   ```

   Then log in at [http://localhost:5000](http://localhost:5000) with the username and password you configured.


## Development

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


