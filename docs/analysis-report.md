# stepca-web: Technical Analysis Report

| | |
|---|---|
| **Analysis** | 2026-10-13, revision `67caf4a` (`main`). After the history rewrite (SEC-1), the same code is commit `15c481f`. |
| **Status update** | 2026-10-29, revision `9e6e23c`, 11 commits later |
| **step-ca reference** | `smallstep/certificates` at `v0.30.2-283-g69d3c36f` (local checkout `~/code/perso/certificates`) |
| **Method** | **Analysis:** I read all first-party code (39 Python files, 20 Jinja templates) and checked it against the step-ca source. I also linted it with ruff (F/B/S/E9 rules), compiled it under Python 3.11 and scanned the git history. I did **not** run the app against a live CA, so the UX findings came from reading the templates, routes and JavaScript. **Status update:** I re-checked every finding against the code at `9e6e23c`. The app now has 93 unit tests and 14 end-to-end tests against a real step-ca 0.30.2. I also drove the UI in a browser. |

> **How to read this report.** Sections 1 to 10 keep each finding as it was found at `67caf4a`, so file and line references point at that revision. Each finding now has a status at `9e6e23c`: ✅ fixed, ⚠️ partly fixed, ❌ open. The executive summary and §11 describe the current state.

---

## Executive summary

### Status at `9e6e23c`

Eleven commits (`21c8ab6` to `9e6e23c`) addressed most of the findings:

- **All three critical findings are fixed:**
  - There are no secrets in the history of `main`.
  - Every route needs a login.
  - Revocation hits the right serial. An end-to-end test proves that step-ca then refuses to renew the certificate.
- **The high findings are fixed, with these exceptions:**
  - LDAP still sends passwords in cleartext by default (SEC-6).
  - The certificate inventory is still parsed in full on every view, although no longer quadratically (PERF-1).
  - SEC-5 is mostly fixed, but one bad LDAP default remains.
- **The main medium finding left** is that login has no rate limiting and the app sends no security headers (SEC-9).
- **Of the 52 original findings, 38 are fixed, 10 partly fixed and 4 open.** Re-checking found 2 new low-severity issues (SEC-13, BUG-21).
- **The app is now tested.**
  - 93 unit tests run in CI.
  - 14 end-to-end tests run a real step-ca 0.30.2 on PostgreSQL, with the app on a **read-only** database role.
  - CI also runs ruff and checks the lockfile.

**Verdict now:** reasonable to run on a trusted admin network behind a TLS reverse proxy. Before exposing it more widely, fix LDAP transport (SEC-6) and add rate limiting and security headers (SEC-9).

### Scorecard

| Area | `67caf4a` | `9e6e23c` | What changed |
|---|:-:|:-:|---|
| 1. Architecture | 2 | **3** | **Improved:** one database stack and one shared CA client; the app's data is in its own SQLite file, so step-ca's database is only read. **Still missing:** a service layer and an inventory cache. Config is still read at import. |
| 2. Code quality | 1.5 | **3.5** | **Improved:** tests, CI, a lockfile, ruff and logging; star imports, dead code and unused dependencies removed. **Still there:** 16 broad `except Exception`, no type checker, two near-duplicate certificate parsers. |
| 3. Feature set | 2.5 | **3.5** | **Added:** revocation with a reason, a certificate page, an expiry view, roles and an audit log, admin type change, search, sort and paging. **Still missing:** SSH, EAB keys, provisioner editing, a CA status page with the CRL. |
| 4. UX quality | 2 | **3** | **Improved:** every certificate has its own URL; tables have tools; actions follow the user's role; the revoke dialog names the certificate. **Still there:** leftovers from the AdminLTE template (top nav, dashboard icons, menu highlighting, login page) and raw dates on some pages. |
| 5. step-ca integration | 2.5 | **4** | **Improved:** correct serials, pinned TLS, full pagination, a dedicated ADMIN identity, the key decrypted in memory, tests against a real step-ca. **Still missing:** a version check. PostgreSQL is the only supported database. |
| 6. Security | 1 | **3.5** | **Improved:** login required by default, CSRF protection, roles, an audit log, TLS verification, gunicorn as a non-root user, no secrets in the repo. **Still open:** LDAP sends passwords in cleartext by default; no rate limiting or security headers. |

### Finding status

| Area | ✅ Fixed | ⚠️ Partly fixed | ❌ Open | New at `9e6e23c` |
|---|:-:|:-:|:-:|---|
| Security (SEC-1 to SEC-12) | 9 | 3 | 0 | SEC-13 (Low) |
| step-ca integration (INT-1 to INT-10) | 7 | 2 | 1 | |
| Correctness (BUG-1 to BUG-20) | 20 | 0 | 0 | BUG-21 (Low) |
| Architecture (A-1 to A-9) | 2 | 4 | 3 | |
| Performance (PERF-1) | 0 | 1 | 0 | |
| **Total (52)** | **38** | **10** | **4** | **2** |

Appendix B lists every finding with its status. §11 orders what is left.

### What is left, most important first

| ID | Severity | What remains |
|---|---|---|
| [SEC-6](#sec-6-high-cleartext-and-unverified-transport) | High | LDAP defaults to `ldap://` with a simple bind, so passwords cross the network in cleartext. `ldaps://` encrypts, but ldap3 does not validate the server certificate by default. |
| [SEC-9](#sec-9-medium-session-and-login-hardening) | Medium | `/auth/login` has no rate limiting or lockout. No CSP, HSTS or frame-ancestors headers are sent. |
| [SEC-5](#sec-5-high-no-authorization-model) | Medium | When `LDAP_BASE_DN` is set, `LDAP_REQUIRED_GROUP_DN` still defaults to it, which refuses every LDAP login. The roles make this setting redundant. |
| [PERF-1](#8-performance-and-scalability) | Medium | Lists parse every certificate on each view. The dashboard does it twice, once on the server and once for its chart through `/api/x509/certs`. |
| [INT-10](#int-10-low-documentation-mismatch) / [§10](#10-documentation-accuracy) | Low | The README still advertises SSH certificates, a "Remote Provisioner", and RADIUS/SAML/OIDC login, and its to-do list is out of date. |
| [§4](#4-ux-quality) | Low | Template leftovers, raw dates on the ACME and Revoked pages, and lost flash messages (BUG-21). |

### Original assessment (`67caf4a`)

stepca-web is a Flask + AdminLTE admin console for a [step-ca](https://github.com/smallstep/certificates) instance that uses PostgreSQL and has remote management (`enableAdmin`) turned on.

- **Reads:** it reads step-ca's internal key/value tables directly from the database to list certificates, ACME objects, provisioners and admins.
- **Writes:** it acts through step-ca's Admin API, using an x5c admin token. It signs and revokes through `/1.0/sign` and `/1.0/revoke`, using a JWK one-time token.
- **Host control:** it can start and stop the CA's systemd service through `sudo`.

**Strengths.** The protocol work is good. The app builds step-ca-compatible x5c admin tokens. It decrypts PBES2-encrypted provisioner keys. It mints JWK one-time tokens (OTTs). It generates JWK provisioners that step-ca accepts. Doing all this in Python without an SDK requires a real understanding of step-ca internals.

**Weaknesses.** Everything around that core is still at prototype level. One core operation, revocation, silently does the wrong thing. Several advertised features are broken or missing. The security posture is far below what a component holding **CA super-admin credentials and a plaintext provisioner signing key** needs.

**Verdict at `67caf4a`:** a promising proof of concept that was **not safe to expose on any network**. The architecture is fine for an admin tool of this size. Most problems could be fixed incrementally, and a rewrite was not needed. The status update confirms this: the findings were fixed without a rewrite.

#### Top findings at `67caf4a`

| ID | Severity | Finding | Status at `9e6e23c` |
|---|---|---|---|
| [SEC-1](#sec-1-critical-secrets-in-public-git-history) | Critical | The public GitHub history contains a **decrypted admin JWK private key**, two private keys and a `settings.json` with the DB password. | ✅ |
| [SEC-2](#sec-2-critical-15-of-26-routes-have-no-authentication) | Critical | 15 of 26 functional routes are unauthenticated. Anyone who can reach the app can **create a SUPER_ADMIN, delete provisioners or admins, and stop the CA**. | ✅ |
| [INT-1](#int-1-critical-revocation-revokes-a-serial-that-does-not-exist) | Critical | Revoking from the UI records a **non-existent serial** in step-ca, so the real certificate stays valid. The UI still shows it as revoked, which hides the problem. | ✅ |
| [SEC-3](#sec-3-high-werkzeug-debug-server-is-the-production-entrypoint) | High | `app.run(debug=True, host="0.0.0.0")` is the Docker `CMD`. | ✅ |
| [SEC-4](#sec-4-high-no-csrf-protection-destructive-get-endpoints) | High | There is no CSRF protection anywhere, and delete actions are plain GET links. | ✅ |
| [INT-2](#int-2-high-revocation-status-is-computed-with-the-wrong-encoding) | High | Certificates revoked with `step ca revoke`, through ACME or over mTLS are shown as **Active**. | ✅ |
| [INT-4](#int-4-high-tls-verification-disabled-root-fingerprint-unused) | High | TLS verification is off for all CA traffic (`verify=False`), and the configured root fingerprint is never used. | ✅ |
| [PERF-1](#8-performance-and-scalability) | High | Listing certificates is O(N²) in database rows, and the dashboard does it three times per view. | ⚠️ O(N) now |
| [INT-3](#int-3-medium-admin-api-pagination-ignored-silent-truncation-at-20) | Medium | Admin API pagination is ignored. Only the first 20 provisioners and 20 admins are ever shown or usable. | ✅ |
| [BUG-13](#23-correctness-bugs) | Medium | ACME provisioner creation is blocked by a hidden `required` field. Admin "Edit" creates duplicates. Several buttons do nothing. | ✅ |

---

## 1. Architecture

### 1.1 Context and prerequisites

To work, the app needs:

- step-ca with **PostgreSQL** as its database and **remote management** enabled (`authority.enableAdmin: true`, i.e. `step ca init --remote-management`).
- `jwk_key.json` in the working directory: the **decrypted** private JWK of the "Admin JWK" provisioner. Per the README, this is produced with `step crypto jwe decrypt`.
- `settings.json` in the working directory: DB credentials, CA URL and root fingerprint.
- For service control: a sudoers rule plus `/usr/local/bin/stepca_ctl.sh`. Neither is in the repo or documented.
- An LDAP/AD server (the default auth backend), or local users hard-coded in source.

**At `9e6e23c`:**
- **step-ca:** PostgreSQL and remote management are still required. A **read-only** database role is enough.
- **Admin key:** `jwk_key.json` is replaced by `CA_ADMIN_PASSWORD_FILE`, the password of the app's own provisioner (in Docker, a secret file). The app decrypts that provisioner's key in memory. `jwk_key.json` still works as a legacy fallback and logs a warning.
- **Configuration:** comes from environment variables (`.env.example` documents them), and `settings.json` is optional. `SECRET_KEY`, `CA_URL` and `DATABASE_HOST` are required.
- **Service control:** off unless `SERVICE_CONTROL_ENABLED=true`. When on, it still needs the undocumented script and sudoers rule.
- **Users:** LDAP, or local users from `local_users.json` with a role each.

### 1.2 Component view

At `67caf4a`:

```mermaid
flowchart LR
  subgraph B["Browser"]
    UI["Jinja pages<br/>jQuery + fetch()"]
  end
  subgraph W["stepca-web (Flask)"]
    BP["Blueprints<br/>home, acme, x509, step, system, auth"]
    LIB["libs<br/>db_*.py, stepapi.py, cert_utils.py"]
    AUTH["Auth backends<br/>LDAP, local (OIDC/SAML/RADIUS = stubs)"]
  end
  FS[("Working dir files<br/>settings.json, jwk_key.json<br/>admin.crt, admin.key")]
  PG[("PostgreSQL<br/>step-ca nosql tables<br/>+ generated_certs (added by app)")]
  CA["step-ca<br/>/admin/* (x5c token)<br/>/1.0/sign, /1.0/revoke (JWK OTT)<br/>/provisioners"]
  SYS["sudo stepca_ctl.sh<br/>systemd"]
  LDAP[("LDAP / AD")]

  UI -- "forms, GET links, /api/* JSON" --> BP
  BP --> LIB
  BP --> AUTH --> LDAP
  LIB -- "SQLAlchemy ORM + raw psycopg2<br/>reads; writes generated_certs" --> PG
  LIB -- "HTTPS, verify=False" --> CA
  LIB <--> FS
  BP -- "subprocess" --> SYS
  CA --> PG
```

At `9e6e23c`:

```mermaid
flowchart LR
  subgraph B["Browser"]
    UI["Jinja pages<br/>jQuery, Bootstrap, tables.js (served by the app)"]
  end
  subgraph W["stepca-web (Flask under gunicorn)"]
    MW["Every request: login required,<br/>CSRF token on writes, role checks"]
    BP["Blueprints<br/>home, acme, x509, step, system, auth"]
    LIB["libs<br/>db_*.py, ca.py + stepapi.py, audit.py"]
    AUTH["Auth backends<br/>LDAP, local (OIDC/SAML/RADIUS = stubs)"]
  end
  SECRET[("Docker secret<br/>CA_ADMIN_PASSWORD_FILE")]
  FS[("Working dir /data<br/>admin.crt, admin.key (0600), ca_root.crt")]
  SQ[("SQLite stepca-web.db<br/>audit log, generated_certs")]
  PG[("PostgreSQL<br/>step-ca nosql tables<br/>(read-only role)")]
  CA["step-ca<br/>/admin/* (x5c token)<br/>/1.0/sign, /1.0/revoke (JWK OTT)<br/>/provisioners, /root/{fingerprint}"]
  SYS["sudo stepca_ctl.sh<br/>(only if enabled)"]
  LDAP[("LDAP / AD")]

  UI -- "POST forms with CSRF token, /api/* JSON" --> MW --> BP
  BP --> LIB
  BP --> AUTH --> LDAP
  LIB -- "SQLAlchemy, SELECT only" --> PG
  LIB --> SQ
  LIB -- "HTTPS, verified against the pinned root" --> CA
  LIB <--> FS
  SECRET --> LIB
  BP -.->|"subprocess, if SERVICE_CONTROL_ENABLED"| SYS
  CA --> PG
```

### 1.3 Code organisation

| Layer | Location | Responsibility | Notes at `67caf4a` | At `9e6e23c` |
|---|---|---|---|---|
| Entry and config | `run.py`, `config.py` | Start the dev server; load `settings.json`, with env override | Config is read **at import time** (`config.py:9`) | Settings come from env vars, and `settings.json` is optional. They are still read at import. |
| App factory | `app/__init__.py` | Register 8 blueprints; create the `generated_certs` table | Runs DDL against the CA database at startup (`app/__init__.py:23-26`) | Creates only the app's own SQLite tables. Installs the login check, CSRF and role helpers. Refuses to start without the required settings. |
| Routes | `app/blueprint/{home,acme,x509,step,system,auth}` | HTML views plus two small JSON APIs (`/api/acme/*`, `/api/x509/*`) | Business logic lives in the route functions | Unchanged |
| Data access | `app/libs/db_*.py`, `app/models/*.py` | Decode step-ca's key/value tables | **Two mechanisms:** SQLAlchemy ORM (X.509, ACME) and raw psycopg2 with a connection per call (provisioners, admins) | SQLAlchemy only (psycopg 3). The X.509 decoding rules live in `db_x509.py`. |
| CA client | `app/libs/stepapi.py` (535 lines) | Admin API, sign, revoke, JWK generation | One large class plus a `CAToken` helper | One shared instance in `app/libs/ca.py`. It loads the key lazily and caches the app's admin type. |
| Crypto helpers | `app/libs/cert_utils.py` | Parse certificates and CSRs | Two near-duplicate parsers | Unchanged |
| Auth | `app/auth/`, `app/libs/auth/` | Backend factory and `login_required` | Only LDAP and local are implemented | Adds the login check for every request (`decorator.py`) and roles (`roles.py`) |
| UI | `app/templates/`, `app/static/` | AdminLTE 3 / Bootstrap 4 / jQuery | 1,891 vendored static files (65 MB), about 6 of them used | 27 static files (4 MB) |

### 1.4 Main flows

1. **Read path** (for example, *Active certificates*): `db_x509.get_x509_active_certs()` loads every row of `x509_certs`. For each row it then loads **every** row of `x509_certs_data` to find the matching provisioner (`db_x509.py:19,43-52`). It then loads every revoked row, parses each DER certificate with `cryptography`, filters by date and renders all of them, with no pagination.
   **Now:** one query per table. Revoked serials come from the table keys and certificates are matched by decimal serial. The browser pages through the rendered rows 50 at a time.
2. **Admin write path** (for example, *create admin*): `StepCAClient._request()` calls `_get_jwt_token()`. If `admin.crt` is missing or has less than 1 hour left, the client generates a P-256 key and CSR. It then signs an OTT with the plaintext `jwk_key.json`, calls `/sign` and **writes `admin.crt` and `admin.key` to the working directory** (`stepapi.py:143-201`). Finally it builds an x5c JWT (`iss=step-admin-client/1.0`, `aud=<request URL>`) and calls `/admin/...`.
   **Now:**
   - The certificate is also renewed when it was issued to another subject or by another provisioner.
   - Renewal holds a file lock.
   - The key is written first, with mode `0600`, and both files are replaced atomically.
   - The admin key comes from memory.
   - Requests are verified against the pinned root.
   - The token audience is the request URL without its query string.
3. **Sign and revoke path:** the user types a provisioner passphrase. The app fetches `/provisioners`, decrypts the provisioner's `encryptedKey` (PBES2 JWE) in memory, mints a JWK OTT and posts it to `/1.0/sign` or `/1.0/revoke`. Signed certificates and their CSRs are also stored in `generated_certs`.
   **Now:**
   - **Sign:** unchanged, except that `generated_certs` is in SQLite.
   - **Revoke:** asks for no passphrase. It uses the app's own provisioner key, sends the decimal serial and the chosen reason, and is recorded in the audit log.
4. **Service control:** `POST /step/service/<action>` runs `sudo /usr/local/bin/stepca_ctl.sh <action>` (`step/routes.py:120`).
   **Now:** returns 404 unless `SERVICE_CONTROL_ENABLED=true`. It needs the admin role, has a 60 s timeout and is audited.

### 1.5 Trust boundaries and secrets held

| Secret | Where it lives | What it grants | At `9e6e23c` |
|---|---|---|---|
| DB credentials | `settings.json` (plaintext) or env vars | Read **and write** access to step-ca's DB. The app needs CREATE privilege for `generated_certs`. Write access means one can forge revocations, edit provisioners and so on. | Env vars (or `settings.json`). A role with SELECT only is enough. |
| Admin JWK private key | `jwk_key.json` (plaintext) | Signs **any certificate** that the "Admin JWK" provisioner allows, and mints super-admin x5c certificates. | Decrypted in memory from `CA_ADMIN_PASSWORD_FILE`. It is the key of the app's own provisioner, and the README recommends an ADMIN rather than a SUPER_ADMIN identity. |
| Admin x5c cert and key | `admin.crt`, `admin.key` (working dir, default umask) | SUPER_ADMIN on the Admin API as subject `step`, for 24 h at a time. | `admin.key` is `0600`. The identity is `CA_ADMIN_SUBJECT` (README: `stepca-web`, type ADMIN). |
| Provisioner passphrases | Typed per operation | Decrypt provisioner keys inside the web process. One of them is printed to stdout (SEC-7). | Typed only to sign. Never logged. |
| Flask `SECRET_KEY` | Env var, otherwise random per process | Forging sessions. | Required: the app does not start without it. |
| sudo rule | `/etc/sudoers` (not in repo) | Start and stop the CA. | Only used when service control is enabled |

**Key insight:** stepca-web is a **tier-0 component**. It holds a super-admin identity, a plaintext signing key, write access to the CA's database and control over the CA process. Compromising the web app is equivalent to compromising the CA's issuance policy, so it needs at least the same protection as the CA itself.

**At `9e6e23c`** the app is still tier-0, but a smaller one. It holds an ADMIN identity (not SUPER_ADMIN) and its provisioner key only in memory, and it only reads the CA's database. An ADMIN can still create provisioners, and so can still issue certificates.

### 1.6 Assessment

**Strengths**
- The app factory plus one blueprint per domain is a clean and familiar Flask layout. A newcomer can find things quickly.
- The data-access, CA-client and route layers are roughly separated.
- The auth backend factory (`app/auth/factory.py`) is a sensible extension point.
- Server-rendered Jinja suits a low-traffic admin tool. The codebase is small enough to reason about as a whole.

**Weaknesses**

| ID | Issue | Consequence | Status at `9e6e23c` |
|---|---|---|---|
| A-1 | **Side effects at import time:** `config.py` opens `settings.json` and prints; three blueprint modules each create a `StepCAClient` at import (`step/routes.py:9`, `x509/routes.py:12`, `system/routes.py:8`, where it is unused), and each reads `jwk_key.json`. `create_app` runs DDL. | The app can't be imported without real files and a database, so it can't be unit-tested. Config edits need a restart (BUG-16). | ⚠️ **Fixed:** one shared client that loads its key on first use; no print; `create_all` only touches SQLite; tests import the app with env vars only. **Still there:** `config.py` reads env vars and `settings.json` into module constants at import. |
| A-2 | **Two DB stacks and two configs:** SQLAlchemy uses `SQLALCHEMY_DATABASE_URI`, while psycopg2 uses `DB_*`. psycopg2 opens a new connection per call, without pooling, and doesn't close it on exceptions. | The two stacks can point at different databases. Connections can leak. | ✅ `db_conn.py` is gone. Everything goes through SQLAlchemy with psycopg 3 (`9ab380e`). |
| A-3 | **Two sources of truth for provisioners:** the Admin API (provisioner page) and direct DB reads (`get_step_provisioners`, used for maps, dropdowns and the dashboard). | The two can disagree, for example on pagination or deleted items. | ❌ **Unchanged, and partly necessary:** the Admin API lists provisioners without their id, so the id-to-name map has to come from the database. Both sides now return every item. |
| A-4 | **The app writes its own table into step-ca's database** (`generated_certs`). | The app needs CREATE on the CA's database and can't run with a read-only role. The table is also redundant, because `x509_certs` already stores the DER of every certificate. | ✅ App data is in SQLite (`21c8ab6`, `f6b09ce`). Downloads read `x509_certs`. The end-to-end tests run the app on a SELECT-only role. |
| A-5 | **No service layer.** Domain rules (what counts as "active") and presentation (`not_before_pretty`) are mixed into data functions. | Hard to test, and hard to reuse in an API. | ❌ Open |
| A-6 | **Coupled to step-ca's internal storage format** (nosql key/value tables and Go JSON field names). | This is unavoidable for listing certificates, since open-source step-ca has no list-certificates API. It should be isolated in one adapter with fixture-based tests. Today the knowledge is spread out, and part of it is wrong (INT-1, INT-2). | ⚠️ **Fixed:** the encoding is now correct and covered by unit tests on rows in step-ca's format, plus end-to-end tests against step-ca 0.30.2. **Still there:** the knowledge is split across `db_x509.py`, `db_acme.py`, `db_step.py` and `cert_utils.py`, and they return nested dicts. |
| A-7 | **Synchronous full-table reads on every page view**, with no caching. Certificates are immutable, so they are ideal to cache. | See §8. | ❌ Open (see PERF-1) |
| A-8 | **One shared CA identity** (`step`) for every web user. | No attribution in step-ca's logs and no least privilege (INT-5). | ⚠️ **Fixed:** a dedicated identity (`CA_ADMIN_SUBJECT`), and the app's audit log names the user. **Still there:** step-ca's own logs show one subject for every user. |
| A-9 | **State in the working directory** (`settings.json`, `jwk_key.json`, `admin.crt`/`admin.key`, all relative paths). | Behaviour depends on where the process starts. Multiple workers race on the admin certificate (BUG-17). | ⚠️ **Fixed:** the race (file lock). The image's working directory is the `/data` volume. **Still there:** every runtime file is relative to the working directory. |

### 1.7 Recommended target architecture (incremental)

- **Config:** load settings once in `create_app` from env or a file, for example with `pydantic-settings`. No I/O at import time. Make config read-only in the UI, or reload it explicitly. *Status:* ⚠️ the config page is read-only and everything can come from env vars, but loading still happens at import.
- **CA client:** a single `StepCAClient` built in `create_app` and stored in `app.extensions`. It should use a `requests.Session` with the **pinned root** (bootstrapped from the fingerprint, see INT-4), timeouts and retries. Load secrets from a secret store, or keep the key encrypted at rest. *Status:* ⚠️ there is one module-level client, not one in `app.extensions`. It has the pinned root, 30 s timeouts and the key decrypted from a secret file. There is no `Session` and no retries.
- **Data access:** one read-only SQLAlchemy engine for step-ca's tables, behind a `StepDBRepository`. The repository should own the step-ca encoding rules (serial key = decimal ASCII) and return typed dataclasses. *Status:* ⚠️ one read-only engine, but no repository and no dataclasses.
- **App state:** the app's own data (audit log, users and roles, metadata about issued certificates, cached inventory) belongs in a **separate** database or schema, managed with migrations (Flask-Migrate/Alembic). *Status:* ⚠️ the app has a separate SQLite database (`APP_DATABASE_URI` can point elsewhere) holding the audit log and `generated_certs`. Tables are created with `create_all`; there are no migrations yet.
- **Service control:** keep a tightly scoped sudoers rule, or remove the feature and leave CA lifecycle to systemd or Kubernetes. It doesn't work inside the provided container anyway. *Status:* ✅ opt-in, off by default.
- **UI:** keep server-side rendering. Add DataTables, which is already vendored, or HTMX for interactivity. At this size a SPA rewrite would mostly add cost. *Status:* ✅ server-rendered. I didn't restore the vendored DataTables 1.10.21, because it has published XSS advisories. Search, sort and paging come from a 100-line `tables.js` that only reads cells as text.

---

## 2. Code quality

### 2.1 Metrics

| Metric | `67caf4a` | `9e6e23c` |
|---|---|---|
| First-party Python | 39 files, 2,106 lines (about 1,440 SLOC). 243 comment lines, mostly **commented-out code**. | 2,184 lines of app code. Commented-out blocks removed. |
| Templates | 20 files, 2,412 lines | 23 files, 2,454 lines |
| Vendored front-end | 1,891 files, 65 MB, 60 AdminLTE plugin packages, about 6 of them used | 27 files, 4 MB |
| Automated tests | **0** | 93 unit tests (about 1,100 lines), plus 14 end-to-end tests against step-ca 0.30.2 on PostgreSQL |
| CI, linter, type-checker, pre-commit config | **None** | GitHub Actions runs ruff, the unit tests, a lockfile check, and the end-to-end tests with both Dockerfiles. Pre-commit runs gitleaks and ruff. No type checker. |
| Dependency manifest | `requirements.txt` with 16 **unpinned** entries and no lockfile. 5 are unused (`flask-login`, `flask_wtf`, `authlib`, `psutil`, `protobuf`). `gunicorn` is installed but never used. | `pyproject.toml` (11 direct dependencies) + `uv.lock`; `requirements.txt` exported with hashes; gunicorn is the server |
| Logging | 73 `print()` calls (many with emojis) and no `logging` | `logging` only, with no `print()` left. Audit events go to the `stepca_web.audit` logger. |
| ruff (`F,B,S,E9`) | 36× F405 + 13× F403 (star imports), 8× F401 unused imports, 7× F811 redefinitions, 4× S113 requests without timeout, 4× F541, 3× F841, plus S104, S110, S311, S501, S603, S607 | Clean on the CI rule set (`E4,E7,E9,F,I,UP,B`). No star imports, and every request has a timeout. |
| Python version | **Requires 3.12+.** `step/routes.py:62,64` reuses the same quote character inside f-strings (PEP 701), which fails on 3.11 with `SyntaxError: f-string: unmatched '['`. I verified this. The README says "Python 3.9+". | `requires-python = ">=3.12"`; the README says 3.12+ |

### 2.2 Strengths

- Database access uses the ORM or parameterised SQL (`db_jwk.py`), so I found no SQL injection.
- `subprocess` gets a fixed argv list and the action is checked against an allow-list (`step/routes.py:116-120`), so there is no shell injection.
- Jinja autoescaping protects all server-rendered output.
- Local passwords use Werkzeug's scrypt hashing.
- The cryptographic code uses well-established libraries (`cryptography`, `jwcrypto`) and does not hand-roll primitives.

### 2.3 Correctness bugs

All 20 are fixed, mostly in `89b419e`, with BUG-8 also in `f6b09ce` and BUG-16 in `763da5a`. Unit or end-to-end tests cover most of them.

| ID | Location | Defect | Effect | Status at `9e6e23c` |
|---|---|---|---|---|
| BUG-1 | `app/blueprint/step/routes.py:18-61` | `resp` is only assigned inside two independent `if` branches | Any other `type` value raises `UnboundLocalError` (HTTP 500) | ✅ An unknown type shows an error message |
| BUG-2 | `step/routes.py:66-67`, `stepapi.py:285-287` | `list_provisioners()` returns `None` on error, and the route then indexes it | Any CA or API error gives HTTP 500 instead of an error message | ✅ Shows "Could not load the provisioners" |
| BUG-3 | `stepapi.py:176-183` | `data` is undefined when `/sign` does not return 201 | Failure to bootstrap the admin certificate raises `UnboundLocalError`, which hides the real CA error | ✅ Raises with step-ca's status and message |
| BUG-4 | `stepapi.py:389-390` | `list_admins()` ignores the HTTP status | An error body crashes the template with a `KeyError` | ✅ Returns `None` on error, and the page shows a message |
| BUG-5 | `stepapi.py:429-440` | `public_get_provisioner_by_name` returns `None` when the provisioner isn't found, and only searches the first page (INT-3) | Sign or revoke shows `'NoneType' object is not subscriptable` to the user | ✅ Searches every page and raises "Provisioner '…' not found on the CA" |
| BUG-6 | `stepapi.py:496-498` | `health()` uses `self.url` and `self.cert_bundle_fn`, which don't exist | Broken (also dead code) | ✅ Removed |
| BUG-7 | `stepapi.py:55-69` | `CAToken.decrypt_and_merge` calls `jose.jwk.JWK.from_password`, which doesn't exist | Broken duplicate of `stepapi.py:521` | ✅ Removed, along with python-jose |
| BUG-8 | `x509/routes.py:43-45` | `url_for("x509/x509.active_certs")` is not a valid endpoint, and the flash message prints `None` | Downloading an unknown serial raises `BuildError` (HTTP 500) | ✅ Redirects with "Certificate … not found". Downloads now work for every certificate. |
| BUG-9 | `db_x509.py:19-22` | A certificate with no `x509_certs_data` row raises `TypeError` | A valid certificate is shown as `[error decoding cert]` | ✅ Listed, with no provisioner |
| BUG-10 | `db_x509.py:125` | A revoked row that failed to parse has no `"Serial"` key | One bad row breaks both the *Active* page and the dashboard | ✅ Revoked serials come from the table keys |
| BUG-11 | `templates/step/admin.html:170` + `step/routes.py:81-94` | The *Edit admin* form posts to the **create** handler, and `admin_id` is ignored | "Edit" creates a **duplicate** admin | ✅ Edit changes the admin's type through `PATCH /admin/admins/{id}`, the only field step-ca lets you change |
| BUG-12 | `templates/step/provisioners.html:262-267` | The *Save* handler only calls `console.log` | Editing a provisioner does nothing | ✅ The dead form is replaced by a read-only view. Editing is a missing feature (§3.3). |
| BUG-13 | `templates/step/provisioners.html:210-214` | The passphrase field is `required` inside a `display:none` block, and ACME is the default type | The browser refuses to submit, so **ACME provisioners cannot be created** | ✅ Only the selected type's fields are shown, required and submitted. Checked in a browser. |
| BUG-14 | `templates/x509/all_certs.html:75,79` | `loadX509Cert` isn't defined on this page, and *revoke* links to `GET /x509/revoke/<id>`, which doesn't exist | The view and revoke buttons on *All* are dead (JS error, then 404) | ✅ Every list links to the certificate page, which can revoke |
| BUG-15 | `templates/acme/orders.html:84` | `loadCert()` and `#certModal` don't exist | The order "View" certificate link is dead | ✅ Links to the certificate page |
| BUG-16 | `system/routes.py:26-42` | Writes `settings.json`, but config is only read once at import | The UI says "updated successfully" but nothing changes until restart | ✅ The config page is read-only and shows the settings in effect, with secrets masked |
| BUG-17 | `stepapi.py:186-199`, `stepapi.py:203-206` | Any worker rewrites `admin.crt` and `admin.key` non-atomically when the certificate is close to expiry | With several gunicorn workers, a request can load a mismatched cert and key | ✅ File lock around renewal and reading; atomic writes, key first |
| BUG-18 | `config.py:51-53` | `SECRET_KEY` is random per process when unset | Sessions are lost on every restart, and with N workers users get logged out at random | ✅ Required at startup |
| BUG-19 | `templates/home/index.html:218` | `cert.provisioner.name` throws for entries without a `provisioner` key (the BUG-9 error rows) | The whole "issuance" bar chart fails to render | ✅ Every entry has a `provisioner` object, and the chart has an empty state |
| BUG-20 | `blueprint/acme/api.py`, `blueprint/x509/api.py` | Empty lists return **404** | The dashboard charts break on a fresh CA. The REST semantics are also wrong. | ✅ Empty lists return `[]` |
| **BUG-21** (new, Low) | `app/templates/*` | Flash messages are rendered on only 7 pages. *All*, *Expiring*, *Revoked*, the ACME pages and the dashboard don't render them. | For example, `/x509/cert/<unknown serial>` redirects to *All* with "Certificate … not found". *All* doesn't show it, so the message appears on whichever page renders flashes next. | ❌ Open: move `includes/flashes.html` into `layouts/base.html` |

### 2.4 Maintainability issues

- ✅ **Star imports everywhere** (`from app.libs.db_acme import *` and others). `system/routes.py` only works because `os` and `json` leak in through `from app.libs.stepapi import *`. *All imports are now explicit.*
- **Duplication:**
  - ❌ `parse_cert` and `parse_cert_from_bytes` are about 80% identical. *Still the case.*
  - ✅ `decrypt_and_merge` exists twice. *One copy left.*
  - ⚠️ The flash-message block is copied into 5 templates. *Now one partial, `includes/flashes.html`, but only `cert_detail.html` includes it. Six other templates still copy the block (BUG-21).*
  - ⚠️ Every template re-declares the font, Font Awesome and AdminLTE CSS links that `base.html` already loads, so `adminlte.min.css` loads twice per page. *JavaScript now loads once, from `base.html`. The CSS links are still repeated in every template.*
- ✅ **Dead code** is removed:
  - `models/post.py` and `models/question.py` (leftovers from a Flask tutorial).
  - `db_jwk.py` and `db_init.py` (the `jwk_keys` table is no longer used).
  - Unused functions: `decode_certificate`, `get_subject_string`, `update_provisioner`, `get_step_admins`, `get_acme_cert_by_id`, `get_x509_certs_data`, `_save_tempfile`. `_compare_fingerprints` is now used to pin the root.
  - `_page_template.html`.
  - About 170 lines of commented-out code in `db_acme.py` and `system/routes.py`.
- ⚠️ **Error handling:**
  - **Then:** broad `except Exception: print(...)` that swallows errors, and raw exception text shown to users (`Failed to sign certificate with error …`).
  - **Now:** the CA's own error messages are passed through, and failures are logged instead of printed. 16 broad `except Exception` remain, and sign and revoke still show raw exception text.
- ✅ **Three JOSE libraries** (python-jose, PyJWT, jwcrypto) for one job. python-jose has had little maintenance and a history of CVEs. Standardise on `jwcrypto`, which is already required for the JWE work. *python-jose is removed. PyJWT signs the tokens and jwcrypto handles the JWE.*
- ✅ **Four `requests` calls without a timeout**, so a hung CA ties up worker threads indefinitely. *Every call has a 30 s timeout.*
- ✅ **Deprecated date handling:** `datetime.utcnow()` and `utcfromtimestamp()` are deprecated in 3.12, and `pytz` is unnecessary. *The code uses `datetime.UTC`, and pytz is removed.*
- ❌ **Weak typing:** almost no type hints, and nested dicts are passed to templates (`cert["data"]["provisioner"]["name"]`). *Unchanged.*
- ✅ **Typos that reach the UI:** "Provisionner" (×3), "Name111", "ACMECertificates". *Fixed.*

### 2.5 Recommendations

1. ✅ Move to `pyproject.toml` + `uv.lock` and pin everything. Remove the unused dependencies and python-jose.
2. ⚠️ Add `ruff` (lint and format) and `pyright` or `mypy`, enforced with pre-commit and GitHub Actions. *ruff is enforced; there is no type checker yet.*
3. ✅ Replace `print` with `logging`, and add a rule that secrets and tokens are never logged.
4. ✅ Remove the dead code, the commented-out blocks and about 98% of the vendored assets.
5. ✅ Add tests (see §9).

---

## 3. Feature set

### 3.1 What the README claims vs. what the code does

| Advertised feature | Status at `67caf4a` | Notes at `67caf4a` | At `9e6e23c` |
|---|---|---|---|
| ACME: "list **and manage**" accounts, orders, certs, authorizations, challenges | ⚠️ Read-only, partial | Flat lists only. No deactivation and no links between related objects. The order → certificate link is broken (BUG-15). The pages are unauthenticated (SEC-2). | ⚠️ Still read-only flat lists, now behind login. Orders link to their certificate. |
| X.509: valid and revoked certificates with details and provisioners | ⚠️ Partial | The lists work. Revoked status is wrong for revocations made outside the UI (INT-2). The details modal only works on *Active*. | ✅ Correct revoked status. Every certificate has a page. New *Expiring* list (7, 30 or 90 days). |
| SSH certificate management | ❌ Missing | No code reads `ssh_certs` or `revoked_ssh_certs`. | ❌ Still missing, still advertised |
| Provisioners: list, add, delete (JWK/ACME) | ⚠️ Partial | The list is capped at 20 (INT-3). Adding a JWK provisioner works. Adding an ACME provisioner is blocked (BUG-13). Edit does nothing (BUG-12). Delete works, but as an unauthenticated GET. | ✅ Every provisioner is listed. JWK and ACME can be added. Delete is a POST that needs the admin role. Details are a read-only view, and editing is not offered. |
| Admin users: view and manage | ⚠️ Partial | List (capped at 20), create and delete work. Edit creates a duplicate (BUG-11). | ✅ List, create, delete and type change. Read-only when the app's identity is an ADMIN, because only a SUPER_ADMIN may manage admins. |
| "Step CA Config Editor: edit and validate `ca.json` with JSON syntax highlighting" | ❌ Not implemented | `/system/config` edits the **app's own** `settings.json` (DB credentials and CA URL). There is no `ca.json` editing and no syntax highlighting. | ✅ The claim is gone from the README. `/system/config` is a read-only view of the app's effective settings. |
| Systemd service control | ⚠️ Works, with external prerequisites | Needs an undocumented sudoers rule and `stepca_ctl.sh`. Unauthenticated. Can't work in the Docker image. | ⚠️ Opt-in, admin role, audited. The script and sudoers rule are still undocumented. |
| Dashboard KPIs | ✅ Works | Expensive (§8). The "Certificate Issuance" chart is actually *certificates per provisioner*, over all time. | ✅ Adds an "expiring within 30 days" tile. Cheaper, but the chart still re-reads the inventory (PERF-1). |
| Sign a CSR | ⚠️ Works for JWK only | ACME provisioners are offered but can't work. Template data is hard-coded (INT-7). Validity can't be chosen. | ⚠️ Template data removed. ACME provisioners are still offered, and validity still can't be chosen. Needs the operator role. |
| Revoke | ❌ **Broken** | Revokes the wrong serial (INT-1). The reason is always keyCompromise (INT-8). | ✅ Correct serial, reason chosen from a list, no passphrase, operator role, audited. Tested end to end: step-ca refuses to renew the revoked certificate. |
| Download a certificate | ⚠️ Partial | Only for certificates signed through this UI (from `generated_certs`). | ✅ Any certificate, from `x509_certs` (leaf PEM only) |
| Auth backends: LDAP, RADIUS, SAML, OIDC, local | ⚠️ Partial | Only LDAP and local are implemented. The other three are stubs that always fail. The README to-do still says "Add user authentication". | ⚠️ Unchanged. LDAP and local now return a role. |

### 3.2 Coverage of step-ca's capabilities

| step-ca capability | Interface | stepca-web at `67caf4a` | At `9e6e23c` |
|---|---|---|---|
| X.509 inventory | DB only (no API) | ✅ List and detail | ✅ Plus the certificate page and the expiring list |
| Sign with a JWK OTT | `POST /1.0/sign` | ✅ | ✅ |
| Revoke | `POST /1.0/revoke` | ❌ Broken (INT-1) | ✅ With a reason |
| CRL | `GET /crl` | ❌ | ❌ |
| Health, version, roots, federation | `GET /health`, `/version`, `/roots`, `/federation` | ❌ (only `systemctl status`) | ⚠️ `/root/{fingerprint}` is used to pin TLS. Nothing is shown in the UI. |
| SSH certificates (inventory, revoke, hosts) | DB + `/1.0/ssh/*` | ❌ | ❌ |
| Provisioners CRUD | `/admin/provisioners` | ⚠️ Create (JWK/ACME), read (≤ 20), delete. Update is missing (`update_provisioner()` exists but is never called). | ⚠️ Create (JWK/ACME), read (all), delete. No update. |
| Other provisioner types: OIDC, X5C, K8sSA, SSHPOP, SCEP, Nebula, AWS/GCP/Azure | `/admin/provisioners` | ❌ | ❌ |
| Claims (renewal, SSH durations, `disableRenewal`, …), x509/ssh templates, options | `/admin/provisioners` | ❌ (only x509 default/min/max durations) | ❌ Same |
| Admins CRUD | `/admin/admins` | ⚠️ Create, read (≤ 20), delete. `PATCH` is missing. | ✅ Create, read (all), type change (`PATCH`), delete |
| ACME External Account Binding keys | `/admin/acme/eab/*` | ❌ So "Require EAB" provisioners can't be used from the UI. | ❌ |
| Policies (authority, provisioner, ACME account) | `/admin/policy`, `/admin/provisioners/{p}/policy`, `/admin/acme/policy/*` | ❌ | ❌ |
| Webhooks | `/admin/provisioners/{p}/webhooks` | ❌ | ❌ |
| ACME objects | DB | ✅ Read-only | ✅ Read-only |

### 3.3 Missing features, ranked by operator value

1. ⚠️ **Expiry monitoring.** An "expiring in 7/30 days" view, a dashboard tile and optional e-mail or webhook alerts. This is the single most useful view for a CA operator. *The view (7, 30 or 90 days) and the tile are done. Alerts were deliberately left out.*
2. ✅ **Search, filter, sort and paginate** every table. *Done in the browser, 50 rows per page. The server still renders every row.*
3. ✅ **A certificate detail page** (`/x509/<serial>`) with PEM, chain and DER downloads for **any** certificate, sourced from `x509_certs`, which removes the need for `generated_certs`. *`/x509/cert/<serial>`. It offers a PEM download of the leaf only, with no chain or DER.*
4. ✅ **Correct revocation** with a choice of reason, available from every list including ACME. *Every X.509 list links to the certificate page, where you can revoke. The ACME certificates page doesn't link there yet.*
5. ✅ **RBAC** (viewer / operator / admin) and an **audit log** of who did what.
6. ❌ **EAB key management**, needed as soon as a provisioner has "Require EAB" ticked.
7. ⚠️ **Provisioner editing** (claims, templates, ACME challenges) through `PUT`, and **admin type change** through `PATCH`. *Admin type change is done; provisioner editing is not.*
8. ❌ A **CA status page**: health, version, roots and fingerprints, CRL download.
9. ❌ **SSH inventory**, then policies and webhooks.
10. ❌ CSV export.

---

## 4. UX quality

### 4.1 Overall impression

AdminLTE gives the app a consistent, recognisable look. The sidebar grouping (ACME / X.509 / step-ca Management / System) is logical. However, the UI still reads like a **template demo with data plugged in**: there are leftovers from the AdminLTE theme, controls that do nothing, and tables that dump raw data. It isn't organised around what an operator needs to do, such as "find the certificate for host X and revoke it" or "what expires this week?".

**At `9e6e23c`,** both of those tasks now work:
- **Find a certificate for a host and revoke it:** search the list, open the certificate, revoke it with a reason.
- **What expires this week:** *Expiring*, 7 days.

The look still shows its template origin.

### 4.2 Template leftovers and dead controls

- ✅ `layouts/base.html:8` declares `<link rel="canonical" href="https://appseed.us/adminlte">`. *Removed.*
- ❌ The top nav has *Home* pointing to `index3.html` (404), *Contact* pointing to `#`, and a search box that does nothing (`includes/navigation.html:9,12,17-26`). *Unchanged.*
- ✅ The sidebar search box (`includes/sidebar.html:19-28`) and the hamburger menu need `adminlte.js`, which is **only loaded on the dashboard**. *`adminlte.js` now loads on every page, so both work. The sidebar search filters menu items.*
- ✅ The dashboard loads AdminLTE's **`demo.js`** (`home/index.html:203`), its theme-customizer demo script. *Removed.*
- ❌ The dashboard tiles use `ion ion-*` icon classes, but the Ionicons CSS is never loaded, so the tile icons are blank. *Unchanged.*
- ❌ Active-menu highlighting depends on a `segment` variable that is never set (`sidebar.html:34`), so the current page is never highlighted. *Revoked* and *All* use a `user-plus` icon. *Unchanged.*
- ⚠️ `auth/login.html` doesn't extend any layout (no `<html>` or `<head>`). It also contains GitHub and Google sign-in buttons that point to a blueprint that doesn't exist (`login.html:67-81`). *Still no layout. The buttons are behind flags that are never set, so they never render, but the dead markup is still there.*

### 4.3 Data presentation

- ✅ **The first column, "Id", on the X.509 pages is the hex encoding of the ASCII decimal serial.** For a 128-bit serial that is 78 meaningless characters, and it is the widest, most prominent column. *It now shows the decimal serial, but the header still says "Id".*
- ⚠️ "Serial" is shown in hex without leading zeros or colons. The step CLI, step-ca logs and `step ca revoke` use **decimal** (or `0x`-prefixed hex), so operators can't cross-reference serials. *The decimal serial is now the first column and is labelled on the certificate page. The hex column is unchanged.*
- ⚠️ Dates are inconsistent. The X.509 pages show "May 22, 2025", while the ACME and revoked pages show raw RFC 3339 with nanoseconds. No timezone is shown, there is no relative time ("in 3 days") and expiry has no colour coding.
  - **Fixed:** the certificate page and the *Expiring* list show a coloured "days left" badge (red under 7 days, amber under 30). Date columns sort by their ISO value.
  - **Still there:** the formats are still mixed.
- ❌ The ACME certificates SAN column renders a Python list repr (`['a.example.com']`) (`acme/certs.html:63`). *Unchanged.*
- ❌ The admin table shows the provisioner **UUID**, even though the view already has a UUID-to-name map. *Unchanged in the table. The edit dialog shows the name.*
- ⚠️ The revoked page doesn't show the reason or reason code. Its "Id" column holds the serial, and its "Serial" column is empty for revocations it can't match (INT-2).
  - **Fixed:** the page names the provisioner each revocation was made with ("Revoked via"). It flags revocations from older versions of the UI that hit the wrong serial, with the certificate that is still valid. The certificate page shows the reason.
  - **Still there:** the list itself doesn't show the reason.
- ❌ Wide tables (10 columns, full RFC 4514 subject **and issuer**, where the issuer is the same on every row) force horizontal scrolling. *Unchanged.*
- ✅ There are no empty-state messages and no pagination, so pages grow without limit. *Lists page 50 rows at a time, and the dashboard charts have an empty state.*

### 4.4 Navigation and information architecture

- ✅ A certificate has **no page or URL of its own**. Details only exist in a modal on *Active*, so you can't link a colleague to a certificate. *`/x509/cert/<serial>`.*
- ❌ The ACME data is five flat menu items for what is really one drill-down (account → orders → authorizations → challenges → certificate). The IDs needed to link them are already present. *Only order → certificate is linked.*
- ⚠️ No global search exists. Both search boxes are cosmetic. *Every table has its own search box, and the sidebar search filters the menu. There is still no global search, and the top-nav box is still cosmetic.*

### 4.5 Forms and workflows

- **Submit CSR:**
  - ❌ The dropdown lists ACME provisioners, which can't sign with a passphrase.
  - ❌ The CSR can only be pasted (no file upload).
  - ❌ There is no way to override validity or SANs, and no preview of the parsed CSR.
  - ⚠️ After a successful signing, the user has to find the certificate in the list to download it. *The success message gives the serial, but doesn't link to the certificate.*
  - ❌ Only the leaf PEM is offered, with no chain or full chain.
- **Revoke:** ✅ every point below is fixed.
  - The modal doesn't say *which* certificate is being revoked. *It now names the subject and serial.*
  - It asks for a "Provisioner Passphrase" without naming the provisioner (it is the admin provisioner). *There is no passphrase any more.*
  - There is no reason field. *There is one now.*
  - It reports success even though the wrong serial was revoked (INT-1). *The right serial is revoked.*
  - It is unavailable on the *All* and ACME pages. *It is on the certificate page, which every X.509 list links to.*
- **Create provisioner:**
  - ✅ Blocked for ACME, the default type (BUG-13).
  - ❌ Durations are free text with no Go-duration validation.
  - ❌ ACME challenge types are hard-coded integers.
- ✅ **Edit provisioner:** dumps the raw JSON, including the encrypted key, as a recursive form, and *Save* does nothing. *It is now a read-only JSON view written with `textContent`. The encrypted key is still shown, but it is public anyway on `/provisioners`.*
- ✅ **Admins:** *Edit* creates a duplicate. The delete confirmation says "delete this **provisioner**". *Edit changes the type, and the confirmation says "admin".*
- **Destructive actions:**
  - ✅ Deleting a provisioner or an admin is a plain GET link guarded only by `confirm()`. *They are now POST forms with a CSRF token, still confirmed with `confirm()`.*
  - ❌ **Stop CA** has no confirmation at all. *Still none, although the page is now opt-in and needs the admin role.*
- ✅ **Config page:**
  - Says "updated successfully" although nothing applies until restart.
  - Pre-fills the password field with the real DB password, which is visible in the page source.
  - *It is now read-only, and the password only shows as "set" or "not set".*

### 4.6 Feedback and errors

- ⚠️ Only 5 templates render flash messages. On every other page, flashed messages are lost. *Now 7, and messages are still lost on the others (BUG-21).*
- ⚠️ Errors appear as raw Python or jwcrypto exception text. For example, a wrong passphrase surfaces a JWE decryption exception. *step-ca's own messages are passed through, but sign and revoke still show raw exception text.*
- ❌ Slow pages have no loading indicator, and all pages load synchronously in full.
- ❌ `step/service.html` uses `fetch` without a `.catch`. If the session has expired, the response is the login HTML, JSON parsing fails, and the user sees nothing.

### 4.7 Accessibility and front-end hygiene

- ⚠️ Icon-only buttons (view, revoke, download, edit, delete) have no `title` or `aria-label`. *Most icon-only buttons now have an `aria-label`. Table headers that sort have `aria-sort`.*
- Library loading is inconsistent:
  - ✅ The dashboard uses a **local** jQuery.
  - ✅ The other pages load jQuery 3.6.0 and Bootstrap 4.6.2 from **CDNs without Subresource Integrity**. *Every page now loads jQuery, Bootstrap and AdminLTE from the app, once, from `base.html`. A test checks that no page loads a script from elsewhere.*
  - ❌ Google Fonts is loaded on every page. *Still loaded, from every template.*
- ⚠️ **PKI environments are often air-gapped.** In such an environment the CDN-loaded scripts and fonts will fail, and modals and forms on most pages will stop working. *Scripts are all local now, so everything works offline. Only the font falls back to a system font.*
- ❌ Bootstrap 4 reached end of life in January 2023, and AdminLTE 3 is built on it.

### 4.8 UX recommendations

**Quick wins (about a day)**

- ⚠️ Remove the template leftovers. *About half are removed (§4.2).*
- ⚠️ Use one base layout that loads jQuery, Bootstrap and AdminLTE **locally**, once. *Done for scripts. The CSS links are still repeated in every template.*
- ✅ Enable DataTables (already vendored) on every table for search, sort and paging. *Done with `tables.js` instead of DataTables (§1.7).*
- ⚠️ Replace the "Id" column with *Serial (dec)* and a copyable *Serial (hex)*. *The decimal serial is shown, but the header still says "Id".*
- ⚠️ Use one date format, plus a "days left" badge (red under 7 days, amber under 30). *The badge is done; the formats are still mixed.*
- ❌ Move the flash partial into `base.html`. *Not done (BUG-21).*
- ✅ Add `aria-label`s.
- ✅ Fix BUG-11 to BUG-15.

**Medium**

- ✅ A certificate detail page with PEM, chain and download links, extensions, provisioner, revocation status and actions. *It has the leaf PEM, provisioner, status, days left, revocation and reason. It has no chain and no list of extensions.*
- ✅ An expiring-soon dashboard.
- ❌ An ACME drill-down.
- ✅ A revoke modal that shows the subject and serial and offers a reason.
- ✅ Modal confirmations for destructive actions, sent as POST. *They are sent as POST, with `confirm()` rather than a modal.*
- ❌ Forms specific to each provisioner type.

**Larger**

- ✅ A UI that adapts to the user's role. *Buttons and forms only show for roles that can use them, and the server enforces the roles too.*
- ✅ An audit-trail view. *System > Audit Log, for admins.*

---

## 5. Integration with step-ca

### 5.1 Integration surfaces

| Surface | Mechanism at `67caf4a` | Used for | At `9e6e23c` |
|---|---|---|---|
| PostgreSQL, step-ca tables | SQLAlchemy models over `x509_certs`, `x509_certs_data`, `revoked_x509_certs`, `acme_*`; psycopg2 over `provisioners`, `admins` | Inventory and dashboards | SQLAlchemy only, SELECT only |
| PostgreSQL, app table | `generated_certs` (created by the app) | Download of UI-signed certificates | Moved to the app's SQLite database. Downloads read `x509_certs`. |
| Admin API | x5c JWT from a self-issued 24 h admin certificate | Provisioners and admins CRUD | Same, as `CA_ADMIN_SUBJECT`, verified against the pinned root |
| Public API | JWK OTT from a passphrase-decrypted provisioner key | `/1.0/sign`, `/1.0/revoke`, `/provisioners` | Revoke uses the app's own provisioner key, held in memory. `/root/{fingerprint}` pins TLS. |
| Host | `sudo stepca_ctl.sh` | start / stop / restart / status | Opt-in |

### 5.2 What the integration gets right

- **The x5c admin token matches what step-ca checks**: ES256, `x5c` chain, `iss = "step-admin-client/1.0"`, `aud` = request URL and a non-empty `sub` (`certificates/authority/authorize.go:147-165`).
- **JWK provisioner creation is compatible with step-ca.** It uses a P-256 key, `kid` = RFC 7638 thumbprint, and a PBES2-HS256+A128KW JWE for the encrypted key. The payload is sent in the linkedca `details.JWK` shape.
- **Provisioner rows are decoded correctly.** `details` is base64-encoded JSON in `dbProvisioner` (`certificates/authority/admin/db/nosql/provisioner.go:16-28`). The soft-delete marker `deletedAt == 0001-01-01T00:00:00Z` (Go's zero time) is handled correctly.
- **ACME `leaf`** (PEM bytes, base64 inside JSON) is decoded correctly.
- **`passive: true` is used**, which is the only revocation mode step-ca implements (`certificates/api/revoke.go:45-47`).
- **The defaults match what step-ca creates** on first start with remote management: provisioner "Admin JWK" and super admin `step` (`certificates/authority/provisioners.go:378`, `certificates/authority/authority.go:708-714`).

One correction found while fixing INT-3: step-ca checks the admin token's `aud` against the URL **path** only. Pagination parameters must therefore stay out of the audience, or step-ca rejects the token. The client now sends them as query parameters outside the signed URL.

### INT-1 (Critical): revocation revokes a serial that does not exist

> **Status at `9e6e23c`: ✅ Fixed** (`21c8ab6`).
> - **Serial:** certificates are identified by their decimal serial, and `revoke()` sends it in decimal (`str(int(serial, 10))`) as both the serial and the token subject.
> - **Tests:** the unit tests check the payload. The end-to-end test signs a certificate from the UI and revokes it, then checks that `step ca renew` is refused.
> - **Past revocations:** the *Revoked* page flags revocations made by older versions of the UI and names the certificate that is still valid. That replaces the clean-up script below; re-revoke those certificates from their page.

**How step-ca stores certificates.** The key of a certificate in `x509_certs` is the **decimal serial as ASCII bytes** (`certificates/db/db.go:324`):

```go
db.Set(certsTable, []byte(crt.SerialNumber.String()), crt.Raw)
```

**How stepca-web builds the identifier.** It uses the hex of those ASCII bytes as the certificate "ID" (`app/libs/db_x509.py:16`), then sends that ID as the serial to `/1.0/revoke` (`app/blueprint/x509/routes.py:104` → `app/libs/stepapi.py:442-452`).

**How step-ca parses it.** step-ca parses the serial with `big.Int.SetString(s, 0)` (`certificates/api/revoke.go:37`). With base 0, a string without a `0x` prefix is read as **decimal**. Hex-of-ASCII consists of digits only (`3x` pairs), so it is accepted as a valid but **different** number. The OTT subject is set to the same string, so the subject check passes (`certificates/authority/tls.go:626`), and step-ca happily stores a revocation for a serial that was never issued.

I reproduced the transformation with a typical 128-bit serial:

```
real serial (dec):       119960802063269571811733802872440608485
cert_id sent to /revoke: 313139393630383032303633323639353731383131373333383032383732343430363038343835
serial step-ca revokes:  313139393630383032303633323639353731383131373333383032383732343430363038343835
same certificate?        False
```

**Impact**
- The real certificate is **not revoked**. `IsRevoked(<real serial>)` returns false (`certificates/db/db.go:181`), so **renewal keeps working**. The CRL contains a bogus serial instead of the real one (`certificates/authority/tls.go:819`).
- **The UI hides the failure.** Its own "is revoked" check uses the same wrong encoding (INT-2), so the certificate disappears from *Active* and shows up under *Revoked*. The operator believes it worked.
- Every revocation made through the UI so far needs to be re-done.

**Fix**

```python
# db_x509.py: step-ca's key *is* the decimal serial string
serial_dec = row.nkey.decode("ascii")
...
client.revoke(serial_dec, passphrase)          # or f"0x{serial_int:x}"
```

**Clean-up of past UI revocations** (run in `flask shell`, read-only):

```python
import json, re
from app.models.x509 import X509Cert, RevokedX509Cert
issued = {bytes(r.nkey) for r in X509Cert.query.with_entities(X509Cert.nkey)}
for r in RevokedX509Cert.query.all():
    s = json.loads(r.nvalue)["Serial"]
    if re.fullmatch(r"(3[0-9])+", s) and bytes.fromhex(s) in issued:
        print("re-revoke:", bytes.fromhex(s).decode())   # then: step ca revoke <serial>
```

### INT-2 (High): revocation status is computed with the wrong encoding

> **Status at `9e6e23c`: ✅ Fixed** (`21c8ab6`). Revoked serials are read from the keys of `revoked_x509_certs` and compared with the decimal keys of `x509_certs`. A unit test covers certificates revoked outside the UI.

`get_x509_active_certs()` compares `revoked.Serial` (decimal, as stored by step-ca) with `cert.nkey` (hex of ASCII) (`db_x509.py:125-133`). `get_revoked_x509_with_cert_info()` makes the same mistake (`db_x509.py:77`). As a result:

- Certificates revoked with `step ca revoke`, through ACME `revokeCert` or over mTLS are **listed as Active** and counted as active on the dashboard.
- The *Revoked* page can't resolve their subject, issuer or serial.

**Fix:** normalise both sides to the decimal string (`nkey.decode()`). Display decimal and hex side by side.

### INT-3 (Medium): Admin API pagination ignored, silent truncation at 20

> **Status at `9e6e23c`: ✅ Fixed** (`495c8ef`).
> - **Paging:** `_list_all()` asks for 100 items per page and follows `nextCursor`, and stops if a cursor repeats. It is used for `/admin/provisioners`, `/admin/admins` and `/provisioners`.
> - **Single provisioner:** still found by scanning the public list, now across every page.
> - **Test:** the end-to-end test creates more than 20 provisioners.

`/admin/provisioners`, `/admin/admins` and the public `/provisioners` return at most **20** items by default, plus a `nextCursor` (`certificates/authority/provisioner/collection.go:22`, `certificates/authority/administrator/collection.go:14`). The client never sends `limit` and never follows the cursor (`stepapi.py:285-287,389-390,429-440`). As a result:

- Provisioners and admins beyond the 20th are invisible.
- Signing or revoking with a provisioner that isn't on the first page fails with BUG-5.

**Fix:** loop with `?limit=100&cursor=…`. To fetch a single provisioner, use `GET /admin/provisioners/{name}` instead of scanning the public list.

### INT-4 (High): TLS verification disabled, root fingerprint unused

> **Status at `9e6e23c`: ✅ Fixed** (`495c8ef`).
> - **Bootstrap:** like `step ca bootstrap`. On first use the app fetches `/root/{CA_FINGERPRINT}`, checks its SHA-256 and saves it as `ca_root.crt`. Alternatively, `CA_ROOT` points at a root file.
> - **Every request** is verified against that root.
> - **Refusals:** the app refuses to talk to the CA without a fingerprint or root, and replaces a cached root that doesn't match the fingerprint.
> - **Not done:** a shared `requests.Session` and retries.

- Every call uses `verify=False`, and urllib3 warnings are silenced globally (`stepapi.py:36,174,254,260`).
- `CA_FINGERPRINT` is configured but only placed in the OTT `sha` claim. `_compare_fingerprints()` is never called.
- With verification off, a network attacker can capture admin tokens and OTTs and feed fake data to the UI.
- **Fix:** step's own trust-bootstrap model. Fetch `GET /root/{fingerprint}` (`certificates/api/api.go:331`), check the SHA-256 locally, save the root, and use it as `verify=` on a shared `requests.Session`.

### INT-5 (Medium): every web user acts as the same CA super admin

> **Status at `9e6e23c`: ⚠️ Option 1 done** (`211ffb0`).
> - **Identity:** `CA_ADMIN_SUBJECT` and `CA_ADMIN_PROVISIONER_NAME` select the app's identity. The README gives the `step` commands to create a `stepca-web` JWK provisioner with an ADMIN of the same name.
> - **ADMIN mode:** with that identity, the Admins page is read-only, because step-ca only lets a SUPER_ADMIN manage admins.
> - **Switching identity:** the app re-issues its admin certificate when the identity changes. It checks the certificate's CN and step-ca's provisioner extension.
> - **Attribution:** the app's audit log records which user did what.
> - **Not done:** options 2 (a policy on the app's provisioner) and 3 (one identity per user). An ADMIN can still create a provisioner and issue certificates with it.

All Admin API calls are made as subject `step` (SUPER_ADMIN) (`stepapi.py:91-100`), so step-ca's logs can't tell which human made a change, and there is no least privilege. Options, from simplest to best:

1. Create a **dedicated** admin for the app, using type `ADMIN` instead of `SUPER_ADMIN` unless admin management is needed. Add a local audit log in the app.
2. Bind the app's JWK provisioner to a **provisioner X.509 policy** that only allows the admin subject. A leaked key could then not mint arbitrary TLS certificates.
3. **Per-user identity:** log users in with OIDC against the same IdP that step-ca's OIDC provisioner trusts, obtain a short-lived x5c admin certificate **per user**, and sign admin tokens with it. step-ca's logs then record the real operator.

### INT-6 (Medium): plaintext provisioner key on disk makes the revoke passphrase meaningless

> **Status at `9e6e23c`: ✅ Fixed, with option (a)** (`211ffb0`).
> - **Key:** with `CA_ADMIN_PASSWORD_FILE` (a Docker secret in `docker-compose.yml`), the app fetches its provisioner's encrypted key from the CA and decrypts it in memory.
> - **Revoke:** no longer asks for a passphrase.
> - **Legacy:** `jwk_key.json` still works, and the app logs a warning when it uses it.

`jwk_key.json` is the **decrypted** key of the admin provisioner. `revoke()` asks the user for that provisioner's passphrase to decrypt the very same key (`stepapi.py:443-448`). The prompt adds friction but no protection, because anyone who controls the server already has the key. Pick one of these:

- (a) Keep only the encrypted key, and decrypt it at startup with a passphrase from a secret store.
- (b) Stop asking for the passphrase.

Option (a) is recommended. In both cases, restrict file permissions to `0600`.

### INT-7 (Low): hard-coded template data copied from the docs example

> **Status at `9e6e23c`: ✅ Fixed** (`89b419e`). Sign requests send no `templateData`.

Every sign request sends `templateData: {"subject": {"country": "US", "organization": "Coyote Corporation", …}}` (`stepapi.py:480-487`). step-ca only exposes this data as `.Insecure.User` (`certificates/authority/provisioner/options.go:166-171`), so it has no effect with the default templates. However, any custom template that uses `.Insecure.User` would stamp "Coyote Corporation / US" on production certificates. Remove it or make it configurable.

### INT-8 (Low): revocation reason fixed to keyCompromise

> **Status at `9e6e23c`: ✅ Fixed** (`89b419e`).
> - **Reasons offered:** unspecified, key compromise, affiliation changed, superseded, cessation of operation, and privilege withdrawn (codes 0, 1, 3, 4, 5 and 9). These are the RFC 5280 reasons that make sense for a passive revocation.
> - **Default:** unspecified.
> - **Display:** the certificate page shows the reason step-ca recorded.

`reasonCode: 1` (keyCompromise) and `reason: "revoked"` are hard-coded (`stepapi.py:452`). This produces misleading CRL entries. Offer the RFC 5280 reasons, which step-ca accepts in the range 0–10.

### INT-9 (Medium): coupling to step-ca's database

> **Status at `9e6e23c`: ⚠️ Partly fixed.**
> - **Done:** the app runs on a read-only role (`generated_certs` moved out). Contract tests run against a real step-ca 0.30.2 in CI.
> - **Not done:** a `GET /version` check at startup, and support for databases other than PostgreSQL. The format knowledge is still spread over several modules (A-6).

- **Unavoidable coupling:** open-source step-ca has no inventory API, so reading the nosql tables is the only option. That makes the app depend on an **undocumented internal format** and on **PostgreSQL** only (step-ca also supports Badger, BoltDB and MySQL).
- **Mitigations:**
  - Use a **read-only DB role**.
  - Move `generated_certs` out of the CA's database.
  - Put all format knowledge in one adapter.
  - Check `GET /version` at startup against a tested range.
  - Add contract tests that run against a real step-ca (§9).

### INT-10 (Low): documentation mismatch

> **Status at `9e6e23c`: ❌ Open.** The README still says "Remote Provisioner" and links to a section of the step-ca docs about provisioners.

The README asks for the "Remote Provisioner". The actual feature is **remote management** (`authority.enableAdmin: true`, `step ca init --remote-management`).

---

## 6. Security

### SEC-1 (Critical): secrets in public git history

> **Status at `9e6e23c`: ✅ Fixed.**
> - **No rotation needed:** the leaked files came from a throwaway local test CA. The production admin provisioner has a different key.
> - **History rewritten:** the history was rewritten and force-pushed, so the files below are no longer reachable from `main`, and the commit hashes in the table no longer exist there.
> - **Local users:** moved out of the source code into `local_users.json`, which is git- and docker-ignored, along with every other secret file.
> - **Scanning:** gitleaks runs as a pre-commit hook.
> - **Residual risk:** the repository's 7 forks may still hold the old history. Since the secrets are harmless, nothing needs to be done about them. gitleaks does not run in CI yet.

`github.com/damhau/stepca-web` is **public**. Its history still contains files that were later deleted:

| File | Added → removed | Content (by structure, values not printed) |
|---|---|---|
| `jwk_key.json` | `ca57e45` → `4793e84` | EC JWK **including the private `d` component**, i.e. a decrypted provisioner key |
| `admin.key`, `_old/_app.old/admin.key` | `ca57e45` → `f11c83b`, `534c698` | PKCS#8 private key (admin x5c certificate, now expired) |
| `svc.key` | `2fef648` → `90e2525` | EC private key (expired leaf issued by a **third-party organisation's** sub-CA) |
| `settings.json` | `876e193` → `1b1151e` | DB host, user and **non-empty password**, CA URL, fingerprint |
| `app/libs/auth/local_backend.py` | current | scrypt hash of the local `admin` password (can be attacked offline if the password is weak) |

**Impact:** if the "Admin JWK" provisioner in that history is still active, anyone can mint certificates from that CA and obtain super-admin access to its Admin API.

**Action, in this order:**

1. Compare `git show ca57e45:jwk_key.json | jq -r .kid` with `step ca provisioner list | jq -r '.[] | select(.name=="Admin JWK") | .key.kid'`. If they match, **create a new admin provisioner, move the super admin to it, and delete the old one**.
2. Rotate the DB password.
3. Change the local admin password, and move local users out of source code.
4. Rewrite history (`git filter-repo`) and force-push, but **treat the secrets as already compromised** regardless: forks and clones may exist.
5. Add `.gitignore` and `.dockerignore` entries and a secret scanner (gitleaks or trufflehog) to pre-commit and CI.

### SEC-2 (Critical): 15 of 26 routes have no authentication

> **Status at `9e6e23c`: ✅ Fixed** (`21c8ab6`).
> - **Login check:** a `before_request` hook requires a session for every endpoint except login, logout and static files. Unauthenticated `/api/*` calls get 401.
> - **Writes:** every write also needs a role (`763da5a`).
> - **Test:** a unit test walks every registered route.

`login_required` is applied route by route, and most routes don't have it (see the full table in Appendix A). **Without logging in**, anyone who can reach the app can:

- **Create a SUPER_ADMIN** on the CA (`GET/POST /step/admins`), using the app's own super-admin identity.
- **Delete any provisioner** (`GET /step/provisioner/<name>/delete`), which takes down issuance, and **delete any admin** (`GET /step/admin/<id>/delete`).
- **Stop or restart the CA** (`POST /step/service/stop`).
- Read the whole ACME inventory, including account contact e-mails and every requested hostname (`/acme/*`, `/api/acme/*`), and the revocation list (`/x509/revoked`).
- Submit revocations (`POST /x509/revoke`). This still needs the passphrase.

**Fix:** deny by default. Use an `app.before_request` hook that requires a session for everything except `/auth/login` and `/static/`, instead of per-route decorators.

### SEC-3 (High): Werkzeug debug server is the production entrypoint

> **Status at `9e6e23c`: ✅ Fixed.**
> - **Docker** (`21c8ab6`): the image runs `gunicorn "app:create_app()"` as a non-root user.
> - **`run.py`** (`8011cc1`): for local development only. It binds to `127.0.0.1` and only enables the debugger with `FLASK_DEBUG=1`.

`run.py:6` calls `app.run(debug=True, host="0.0.0.0")`, and the Dockerfile's `CMD` is `python run.py`. The interactive debugger and reloader are therefore exposed on every interface. Given the number of crash paths (§2.3), stack traces with source code and configuration will be shown to users. The debugger PIN is only weak protection.

**Fix:** run `gunicorn "app:create_app()"`, which is already a dependency, and never enable debug outside local development.

### SEC-4 (High): no CSRF protection, destructive GET endpoints

> **Status at `9e6e23c`: ✅ Fixed** (`495c8ef`).
> - **CSRF:** `CSRFProtect` is on, and every form and `fetch` call sends the token. Tokens stay valid for the session.
> - **Deletes:** only accept POST.
> - **Cookie:** the session cookie is `SameSite=Lax` and `HttpOnly`.
> - **Tests:** cover every POST route.
> - **Remaining:** logout is still a GET, so another site can log a user out. That is harmless.

Flask-WTF is listed as a dependency, but `CSRFProtect` is never initialised. Every POST form, including create admin, create provisioner, sign, revoke and config, can be forged from another site. Deletes are **GET** links, so even an `<img src>` on a page an authenticated admin visits will trigger them.

**Fix:**
- Turn on `CSRFProtect`.
- Make every state change a POST, PUT or DELETE.
- Set `SESSION_COOKIE_SAMESITE="Lax"` or `"Strict"`.

### SEC-5 (High): no authorization model

> **Status at `9e6e23c`: ⚠️ Mostly fixed** (`763da5a`).
> - **Roles:** viewer, operator (also signs and revokes) and admin (also provisioners, admins, configuration, audit log and service control). The server enforces them, and the UI hides what a role can't do.
> - **Role assignment:** LDAP group DNs map to roles through `ROLE_*_GROUP`. Local users carry a role. Anyone else gets `DEFAULT_ROLE` (`viewer`, or `none` to refuse them).
> - **Audit log:** every write, every login and every failed login goes to the audit log (SQLite, shown under System > Audit Log) and to stdout.
> - **Still open:** `LDAP_REQUIRED_GROUP_DN` still defaults to `LDAP_BASE_DN` (`config.py`). When `LDAP_BASE_DN` is set and `LDAP_REQUIRED_GROUP_DN` isn't, every LDAP login is refused. `DEFAULT_ROLE=none` now does the same job, so drop the setting or default it to empty.
> - **Note:** the audit log can be edited by anyone with access to the data volume. Ship stdout to a log system if you need a tamper-resistant copy.

Every authenticated user is effectively a **CA super admin with host service control**. There are no roles. The LDAP group check is the only gate, and it is all-or-nothing. It is also misconfigured by default: `LDAP_REQUIRED_GROUP_DN` falls back to the base DN (`config.py:49`), which no user is a member of.

**Fix:** add roles (viewer / operator / admin), mapped from LDAP or OIDC groups, and keep an audit log of every write.

### SEC-6 (High): cleartext and unverified transport

> **Status at `9e6e23c`: ⚠️ Half fixed.**
> - **CA traffic:** verified (INT-4).
> - **LDAP:** unchanged. It defaults to `ldap://` with a simple bind. `ldaps://` encrypts the connection, but ldap3's default `Tls()` uses `validate=CERT_NONE`, so the server's certificate is not checked.
> - **Login checks:** an empty password is now refused before the bind, because many servers treat it as an anonymous bind and accept it.
> - **To fix:** use a `Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=…)` object and support StartTLS. This needs an LDAP server to test against.

- CA traffic is unverified (INT-4).
- LDAP defaults to `ldap://` with a simple bind, so **user passwords cross the network in cleartext** (`config.py:44`, `ldap_backend.py:20-22`).

**Fix:** require LDAPS or StartTLS, with certificate validation.

### SEC-7 (Medium): secrets in logs

> **Status at `9e6e23c`: ✅ Fixed.**
> - **Logging:** no `print()` is left (the last ones went in `8011cc1`). The code uses `logging`, and nothing logs a passphrase, a token or a payload.
> - **Startup:** `config.py` no longer prints the database connection details.

- `stepapi.py:321` prints the **new JWK provisioner's passphrase** to stdout.
- `stepapi.py:453` and `stepapi.py:488` print full payloads, including one-time tokens. The tokens are short-lived but still sensitive.
- `config.py:38` prints DB connection details at import.

**Fix:** remove these prints and adopt structured logging with redaction.

### SEC-8 (Medium): secrets at rest

> **Status at `9e6e23c`: ✅ Fixed.**
> - **Admin key:** `admin.key` is written with mode `0600` (`89b419e`). The provisioner key stays in memory (`211ffb0`).
> - **Config page:** shows no secrets (`763da5a`).
> - **Docker:** `.dockerignore` keeps every secret file out of the image.
> - **Still possible, but optional:** `settings.json` can still hold the DB password in plaintext (env vars are the documented way), and the legacy `jwk_key.json` still works.
> - **New:** see SEC-13.

- `jwk_key.json`, `admin.key` and `settings.json` are plaintext files in the working directory.
- `admin.key` is written with the default umask, usually `0644`, which makes it world-readable (`stepapi.py:192`).
- The DB password is rendered into the HTML of `/system/config` (`config_edit.html:75`).
- No `.dockerignore` exists, so `COPY . .` bakes any local secrets into the image.

### SEC-9 (Medium): session and login hardening

> **Status at `9e6e23c`: ⚠️ Partly fixed** (`89b419e`, `495c8ef`).
> - **Done:**
>   - `SECRET_KEY` is required, with no random fallback.
>   - Login and logout call `session.clear()`.
>   - Sessions last 8 hours (`SESSION_LIFETIME_HOURS`).
>   - The cookie is `HttpOnly` and `SameSite=Lax`, plus `Secure` with `SESSION_COOKIE_SECURE=true`.
>   - Failed logins are audited.
> - **Still open:** login rate limiting or lockout, and security headers (CSP, HSTS, `frame-ancestors`).

- `SECRET_KEY` falls back to Python's non-cryptographic `random` module (`config.py:51-53`).
- The session ID isn't rotated at login, and logout doesn't clear the session.
- There is no session lifetime and no rate limiting or lockout on `/auth/login`.
- There is no `SESSION_COOKIE_SECURE` and no security headers (CSP, HSTS, frame-ancestors).

**Fix:**
- Use `secrets.token_hex()`, and require it to be set in production.
- Call `session.clear()` on login and logout.
- Set `PERMANENT_SESSION_LIFETIME`.
- Use Flask-Limiter for rate limiting and Flask-Talisman for security headers.

### SEC-10 (Medium): DOM-XSS sinks

> **Status at `9e6e23c`: ✅ Fixed** (`89b419e`).
> - **Provisioner view:** shows the JSON with `textContent`.
> - **Certificate details:** the modal is replaced by the server-rendered certificate page, with autoescaping.
> - **Dashboard chart:** escapes provisioner names.
> - **Tables:** `tables.js` only reads cells as text.
> - **Test:** a unit test checks that certificate fields are escaped.

Two places build HTML from data:

- `provisioners.html:276-327` (`generateForm`) interpolates provisioner keys and values into HTML. Values that contain quotes, such as JSON templates, break the form today.
- `active_certs.html:238-251` writes certificate fields with `innerHTML`.

With step-ca's default templates, attackers can't control these fields: ACME only copies the CSR common name (`certificates/acme/order.go:236`). They become exploitable with custom templates that copy CSR subject fields. In that case a malicious CSR could run script in an admin's browser and drive the (unprotected) admin endpoints.

**Fix:** use `textContent` or build DOM nodes.

### SEC-11 (Low): LDAP filter injection

> **Status at `9e6e23c`: ✅ Fixed** (`89b419e`). The username is escaped with `escape_filter_chars`.

`ldap_backend.py:27` inserts the username into the search filter without escaping. Exploitation is limited because the bind happens first, but the fix is a one-liner: `ldap3.utils.conv.escape_filter_chars`.

### SEC-12 (Low): supply chain and container

> **Status at `9e6e23c`: ✅ Fixed.**
> - **Dependencies:** locked in `uv.lock`, and `requirements.txt` is exported with hashes for `pip --require-hashes` (`9ab380e`).
> - **Front end:** no script comes from a CDN, and the vendored assets are down to 27 files.
> - **Image:** multi-stage and non-root, with no compiler (psycopg 3 binary wheels) and with a `HEALTHCHECK`.
> - **PBKDF2:** the iteration cap is 1,000,000, just above what step uses, and the CA's TLS is verified.
> - **Not done:** automated dependency updates or vulnerability scanning (Dependabot, `pip-audit`). The Google Fonts stylesheet still comes from Google.

- Dependencies are unpinned and there is no lockfile.
- Front-end scripts are loaded from CDNs without SRI.
- The image runs as root and carries `gcc`, `build-essential` and `libpq-dev`. Use `psycopg[binary]` or a multi-stage build.
- There is no `HEALTHCHECK`.
- 60 vendored JS packages bring their own known-vulnerability history without adding anything.
- `jwa.default_max_pbkdf2_iterations` is raised globally to 10,000,000 (`stepapi.py:30`). With TLS verification off, a man-in-the-middle can serve a JWE with a huge iteration count and burn CPU. Cap the limit at what step actually uses.

### SEC-13 (Low, new): the config page shows the app database URI verbatim

`/system/config` masks the step-ca database password, but prints `APP_DATABASE_URI` as it is (`app/blueprint/system/routes.py`). With the default SQLite path that is harmless. If someone points it at a server database with a password in the URI, admins see that password. **Fix:** mask the password with SQLAlchemy's `make_url(uri).render_as_string(hide_password=True)`.

### Threat summary

| Attacker | At `67caf4a` | At `9e6e23c` |
|---|---|---|
| Anyone on the network | CA admin takeover, provisioner deletion, CA shutdown, inventory disclosure | Login page only. No rate limiting, so passwords can be guessed online. |
| Malicious site visited by an admin | Any action through CSRF or a GET link | Blocked (CSRF tokens, SameSite, POST-only). Can only log the user out. |
| Anyone with GitHub access | Possibly a working CA signing key and DB credentials | Nothing: the history of `main` is clean, and the leaked keys were from a test CA |
| Network position between app and CA | Token capture and data spoofing | Blocked by the pinned root |
| Network position between app and LDAP | Captures user passwords | **Unchanged:** captures user passwords over `ldap://`, and can impersonate the server over `ldaps://` (SEC-6) |
| Authenticated low-privilege user | Full super admin | Bound to a role and audited |

---

## 7. Operations and deployment

- **Configuration:**
  - ✅ `settings.json` is **mandatory at import** (`config.py:9`), even when every value is provided by env vars, so 12-factor deployment is impossible. *Optional now: env vars are enough.*
  - ✅ The path is relative to the working directory, while the README says `app/settings.json`. *The README is corrected.*
  - ✅ The env var mapping (`database.host` → `DATABASE_HOST`, …) is undocumented. *Documented in `.env.example`.*
  - ✅ Config changes made through the UI need a restart (BUG-16). *The UI no longer edits config.*
- **Docker:**
  - ✅ The image uses the dev server with debug on (SEC-3), runs as root and keeps the build toolchain. *It runs gunicorn as uid 1000 and contains no compiler.*
  - ✅ It has no `.dockerignore` and no health check.
  - ✅ `jwk_key.json` and the admin certificate need volumes that aren't documented. *`docker-compose.yml` mounts `/data` as a volume and passes the password as a secret.*
  - ⚠️ Service control (`sudo` + systemd) **can't work inside a container**. *Still true, so it is now off by default, and the README says so.*
  - ✅ Python 3.12 in the image is correct and in fact required (§2.1).
  - *New:* `Dockerfile` (uv) and `Dockerfile.pip` (pip with `--require-hashes`) build the same image. Both only need Docker Hub and PyPI, and CI builds both.
- **Process model:**
  - ✅ gunicorn is installed but unused.
  - ✅ Under gunicorn with several workers there was:
    - a different `SECRET_KEY` per worker (BUG-18);
    - a race on the admin certificate (BUG-17);
    - one module-level CA client per worker and per blueprint.

    *All three are fixed: the key is required, renewal is locked, and there is one client per process. The image defaults to 1 worker with 4 threads.*
- **Observability:**
  - ⚠️ Only `print` output, with no request log, no audit log and no `/healthz` for the app itself. *There are now `logging`, a gunicorn access log and an audit log. The Docker health check uses `/auth/login`, and there is no dedicated `/healthz`.*
  - ❌ No metrics, for example on certificates nearing expiry.
- ✅ **Database privileges:** the app needs CREATE on the CA's database at startup. Use a read-only role on step-ca's tables, and give the app its own schema. *SELECT is enough, and the end-to-end tests use such a role.*
- ❌ **Undocumented host prerequisites:** `/usr/local/bin/stepca_ctl.sh` and the sudoers rule. *Still undocumented.*

---

## 8. Performance and scalability

> **Status at `9e6e23c`: ⚠️ Mostly fixed** (`495c8ef`).
> - **Listing:** O(N). Each list runs one query per table and loads `x509_certs_data` once, as a dict.
> - **Single certificate:** looked up by primary key for the certificate page, revocation and the API.
> - **Dashboard:** parses the inventory once on the server, and the three counts share it.
> - **Paging:** done in the browser.
> - **Still open:**
>   - The dashboard's bar chart fetches `/api/x509/certs`, so each dashboard view still parses every certificate **twice**.
>   - Every list view parses every certificate.
>   - Every row is rendered to the browser, which then hides all but 50.
> - **Cost:** parsing alone costs about 33 µs per certificate (0.33 s for 10,000, measured on the development machine). Loading the rows and rendering the HTML weren't measured, and will dominate at that size.
> - **Next steps:** have the chart use counts the server already has, then cache parsed metadata per serial (fix 4 below).

**PERF-1 (High): quadratic certificate listing**

- `get_x509_certs()` runs `X509CertData.query.all()` **once per certificate** to find its metadata (`db_x509.py:19,43-52`). That is **N queries returning N rows each**: O(N²) rows transferred and JSON-decoded, plus N DER parses.
- `get_x509_certs_by_id()`, used by the details modal and by revoke, performs the full O(N²) listing to find one certificate.
- One dashboard view triggers this **three times**:
  1. `get_x509_certs()`
  2. `get_x509_active_certs()`, which calls it again
  3. the browser's `GET /api/x509/certs`

  The *Revoked* page triggers it once more.

**Growth**
- step-ca never purges `x509_certs`, and ACME issues 24 h certificates by default.
- 100 hosts renewing daily produce about 36,500 rows a year. At that size one dashboard view reads about 4 × 10⁹ rows.
- In practice the pages will time out long before that. At just 2,000 certificates, a dashboard view already decodes about 12 million rows.

**Fixes, in order of effort**
1. ✅ Load `x509_certs_data` **once** into a dict keyed by `nkey` (O(N)).
2. ✅ Look up a single certificate by primary key: `WHERE nkey = :serial_ascii_bytes`.
3. ⚠️ Paginate on the server, or render once and let DataTables page on the client as a stopgap. *The stopgap is in place, with `tables.js`.*
4. ❌ Certificates are **immutable**, so cache the parsed metadata per serial, ideally materialised into the app's own table with incremental sync. Querying, filtering by expiry and indexing then become trivial.

---

## 9. Testing strategy

At `67caf4a` there were no tests. At `9e6e23c`, `uv run pytest` runs 93 unit tests in about 13 seconds. `tests/e2e/run.sh` starts step-ca 0.30.2 on PostgreSQL, with the app in Docker on a read-only role, and runs 14 end-to-end tests. CI runs both. Against the suggested layers:

1. ✅ **Unit tests for the decoders.** Use real rows captured from a step-ca Postgres database: `x509_certs`, `x509_certs_data`, `revoked_x509_certs`, `provisioners` (base64 `details`) and `acme_*`. *The X.509 and provisioner rows are built in step-ca's format, not captured, and the end-to-end tests then cover the real tables. There are no ACME decoder unit tests.*
2. ✅ **A regression test for the serial round-trip** (INT-1 and INT-2): decimal key → display → revoke payload → matching against revoked rows.
3. ✅ **Tests for the token builders.** Check x5c and OTT claims (`iss`, `aud`, `sub`, `sans`, `exp`) against the expectations in step-ca's `authorize.go`.
4. ✅ **Integration tests in CI.** Use `smallstep/step-ca` with `DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT=true` and `DOCKER_STEPCA_INIT_ACME=true`, with `ca.json`'s `db` pointing at a Postgres service container. Exercise create/delete provisioner and admin, sign, revoke, then **assert with `step ca revoke` / `/crl` that the right serial was revoked**. *The tests cover signing, downloading and revoking. They then check that `step ca renew` is refused, which is stronger than reading the CRL. They also cover more than 20 provisioners, admin type changes, root pinning, and both identity modes (an ADMIN with a password file, and the SUPER_ADMIN with `jwk_key.json`).*
5. ✅ **Route security tests.** Every route except login and static must return 302 or 401 without a session, and every state-changing route must reject GET and requests without a CSRF token. *Roles are covered too, in 18 tests.*
6. ✅ **Template smoke tests.** Render every page with fixture data. This would have caught BUG-14, BUG-15 and BUG-19.

**Still missing:** a type checker, ACME decoder tests, and browser tests for the JavaScript. The JavaScript was checked by hand with Playwright: the provisioner form, the revoke dialog, the provisioner view and the table tools.

---

## 10. Documentation accuracy

| README statement | Reality at `67caf4a` | At `9e6e23c` |
|---|---|---|
| "Python 3.9+" | 3.12+ (PEP 701 f-strings) | ✅ README says 3.12+ |
| "Edit and validate the `ca.json` file with JSON syntax highlighting" | Not implemented. The page edits the app's `settings.json`. | ✅ Claim removed |
| "SSH Certificate Management" | Not implemented | ❌ Still advertised, twice |
| "Remote Provisioner" | Remote **management** (`enableAdmin`) | ❌ Still "Remote Provisioner" |
| "Edit `app/settings.json`" | `settings.json` in the working directory | ✅ Env vars documented, `settings.json` optional |
| Auth backends `ldap`, `radius`, `saml`, `oidc`, `local` | Only `ldap` and `local` work | ❌ Still lists all five |
| To-do: "Add user authentication" | Partly done, but not applied to most routes | ❌ The to-do list still offers authentication, audit logging and table filtering, which are all done |
| "extend `layout.html`" | `layouts/base.html` | ✅ |
| Service control | Needs an undocumented `stepca_ctl.sh` plus a sudoers rule | ⚠️ Documented as optional and off by default. The script is still undocumented. |
| (missing) | No warning that `jwk_key.json` is a plaintext CA signing key and needs `0600` permissions and backup hygiene | ✅ "CA identity" section: the password file replaces it, and `jwk_key.json` is called legacy |
| (missing) | No Docker usage, env var reference, production run command or upgrade notes | ✅ Docker, env vars (`.env.example`), roles and tests are documented. ❌ No upgrade notes for the breaking changes: required `SECRET_KEY` and Docker secret, `viewer` as the default role. |
| "ACME: list **and manage**" | Read-only | ❌ Still says "manage" |

---

## 11. Prioritised roadmap

### Done since `67caf4a`

- **P0** ✅ All five P0 items:
  - the leaked secrets (no rotation needed; history rewritten; gitleaks);
  - authentication on every route;
  - no debug server;
  - the revoke serial and revocation status;
  - no secrets in logs.
- **P1** ✅
  - CSRF and POST-only state changes; the pinned CA root.
  - Admin API pagination; BUG-1 to BUG-20.
  - `pyproject.toml` + `uv.lock`, ruff, CI and tests.
  - Refactoring of config and the client (mostly); logging; removal of dead code, unused dependencies and assets.
  - The O(N²) read path; Docker hardening.
- **P2** ✅
  - RBAC and audit log; a dedicated CA identity; the key decrypted in memory.
  - A certificate page; expiry view and tile; search, sort and paging.
  - Revocation reasons; admin type change.

### Next

**P1: finish hardening**
1. **LDAP over TLS with certificate validation** (SEC-6): `Tls(validate=CERT_REQUIRED)`, `ldaps://` or StartTLS, optional CA file. Needs an LDAP server to test against.
2. **Login rate limiting and security headers** (SEC-9): Flask-Limiter on `/auth/login`. Set CSP, HSTS and `frame-ancestors`, either in the app or at the reverse proxy.
3. **Drop the `LDAP_REQUIRED_GROUP_DN` default** (SEC-5), and mask `APP_DATABASE_URI` (SEC-13).
4. **README:** remove the claims about SSH, "Remote Provisioner", RADIUS/SAML/OIDC and "manage" ACME, and update the to-do list (INT-10, §10). Add upgrade notes for the breaking changes. Document `stepca_ctl.sh` and its sudoers rule, or drop service control.
5. **Run gitleaks in CI**, and add Dependabot or `pip-audit` (SEC-1, SEC-12).

**P2: product and UX**
- **Flash messages:** render them in `base.html` (BUG-21).
- **Template leftovers:** clear the rest (§4.2), and load the CSS once.
- **Display:** use one date format; show revocation reasons on the *Revoked* list; show provisioner names in the admin table; join the ACME SAN list.
- **Dashboard chart:** take its counts from the server instead of `/api/x509/certs` (PERF-1).
- **Provisioners:** editing through `PUT`, EAB keys, and per-type forms with duration validation.
- **CA status page:** health, version, roots and a CRL download, plus a version check at startup (INT-9).
- **Certificate page:** chain and DER downloads, the list of extensions, and a link from the ACME certificates page.

**P3: scale and breadth**
- **Inventory:** incremental sync and a cache in the app's own database, with server-side paging (PERF-1, A-7).
- **Code structure:** a service layer and typed records (A-5, A-6), and a type checker.
- **More of step-ca:** SSH inventory, policies, webhooks.
- **Notifications:** expiry alerts and metrics.
- **Identity:** a provisioner policy for the app's key, then one CA identity per user (INT-5).

---

## Appendix A: route inventory

### At `67caf4a`

| Auth | Method | Path | Handler | Notes |
|---|---|---|---|---|
| ❌ | GET | `/acme/accounts` | `acme.accounts` | Exposes ACME contact e-mails |
| ❌ | GET | `/acme/orders` | `acme.orders` | Exposes requested hostnames. "View" link is broken (BUG-15). |
| ❌ | GET | `/acme/certs` | `acme.certs` | |
| ❌ | GET | `/acme/authzs` | `acme.authzs` | |
| ❌ | GET | `/acme/challenges` | `acme.challenges` | |
| ❌ | GET | `/api/acme/accounts` | `acme_api.accounts` | JSON. Returns 404 when empty. |
| ❌ | GET | `/api/acme/orders` | `acme_api.orders` | JSON. Used by the dashboard. |
| ❌ | GET | `/api/acme/certs` | `acme_api.certs` | JSON |
| ❌ | GET | `/api/acme/authzs` | `acme_api.authzs` | JSON |
| ❌ | GET | `/api/acme/challenges` | `acme_api.challenges` | JSON |
| n/a | GET, POST | `/auth/login` | `auth.login` | No CSRF and no rate limiting |
| n/a | GET | `/auth/logout` | `auth.logout` | |
| ✅ | GET | `/` | `home.index` | 3× O(N²) per view |
| ✅ | GET, POST | `/step/provisioners` | `step.provisioner` | Shows ≤ 20 items. ACME creation blocked. |
| ❌ | **GET** | `/step/provisioner/<name>/delete` | `step.delete_provisioner` | **Destructive, unauthenticated, GET** |
| ❌ | GET, POST | `/step/admins` | `step.admins` | **Unauthenticated SUPER_ADMIN creation** |
| ❌ | **GET** | `/step/admin/<id>/delete` | `step.delete_admin` | **Destructive, unauthenticated, GET** |
| ❌ | POST | `/step/service/<action>` | `step.stepca_service_action` | **Unauthenticated CA stop and restart** |
| ❌ | GET | `/step/service` | `step.step_service` | |
| ✅ | GET, POST | `/system/config` | `system.config` | DB password rendered into the HTML. No CSRF. |
| ✅ | GET | `/api/x509/certs/<id>` | `x509_api.api_get_x509_certs_by_id` | O(N²) per call |
| ✅ | GET | `/api/x509/certs` | `x509_api.api_get_x509_certs` | O(N²) per call |
| ✅ | GET | `/x509/all` | `x509.all_certs` | View and revoke buttons broken (BUG-14) |
| ✅ | GET | `/x509/active` | `x509.active_certs` | Revoked status wrong (INT-2) |
| ❌ | GET | `/x509/revoked` | `x509.revoked_certs` | |
| ✅ | GET | `/x509/download/<serial>` | `x509.download_cert` | Only UI-signed certificates. 500 on unknown serial (BUG-8). |
| ✅ | POST | `/x509/sign` | `x509.sign_cert` | No CSRF |
| ❌ | POST | `/x509/revoke` | `x509.revoke_cert` | **Revokes the wrong serial (INT-1)** |

### At `9e6e23c`

Every route needs a session except `/auth/login`, `/auth/logout` and `/static/*`. Without one, pages redirect to the login page and `/api/*` returns 401. Every POST needs a CSRF token. *Role* is the minimum role.

| Role | Method | Path | Handler | Notes |
|---|---|---|---|---|
| public | GET, POST | `/auth/login` | `auth.login` | CSRF-protected, clears the session, logs attempts to the audit log. No rate limiting (SEC-9). |
| public | GET | `/auth/logout` | `auth.logout` | Clears the session. A GET, so another site can log a user out. |
| viewer | GET | `/` | `home.index` | Counts, expiring tile, two charts |
| viewer | GET | `/acme/accounts`, `/acme/orders`, `/acme/certs`, `/acme/authzs`, `/acme/challenges` | `acme.*` | Read-only lists. Orders link to their certificate. |
| viewer | GET | `/api/acme/{accounts,orders,certs,authzs,challenges}` | `acme_api.*` | JSON, `[]` when empty |
| viewer | GET | `/api/x509/certs` | `x509_api.api_get_x509_certs` | JSON. Used by the dashboard chart (PERF-1). |
| viewer | GET | `/api/x509/certs/<id>` | `x509_api.api_get_x509_certs_by_id` | Lookup by decimal serial (primary key) |
| viewer | GET | `/x509/all`, `/x509/active`, `/x509/revoked` | `x509.*` | Search, sort and 50-row pages |
| viewer | GET | `/x509/expiring?days=7\|30\|90` | `x509.expiring_certs` | New |
| viewer | GET | `/x509/cert/<serial>` | `x509.cert_detail` | New: status, days left, revocation reason, download, revoke |
| viewer | GET | `/x509/download/<serial>` | `x509.download_cert` | Any certificate, from `x509_certs` |
| operator | POST | `/x509/sign` | `x509.sign_cert` | Provisioner passphrase. Audited. |
| operator | POST | `/x509/revoke` | `x509.revoke_cert` | Decimal serial and a reason. Audited. |
| viewer / admin | GET / POST | `/step/provisioners` | `step.provisioner` | Lists every provisioner. Creating one (POST) needs admin. Audited. |
| admin | POST | `/step/provisioner/<name>/delete` | `step.delete_provisioner` | Audited |
| viewer / admin | GET / POST | `/step/admins` | `step.admins` | Creating one (POST) needs admin **and** a SUPER_ADMIN identity. Audited. |
| admin | POST | `/step/admin/<id>/update` | `step.update_admin` | New: type change (`PATCH`). Needs a SUPER_ADMIN identity. Audited. |
| admin | POST | `/step/admin/<id>/delete` | `step.delete_admin` | Needs a SUPER_ADMIN identity. Audited. |
| admin | GET | `/step/service` | `step.step_service` | 404 unless `SERVICE_CONTROL_ENABLED=true` |
| admin | POST | `/step/service/<action>` | `step.stepca_service_action` | 404 unless enabled. Audited, except `status`. |
| admin | GET | `/system/config` | `system.config` | Read-only, secrets masked (except SEC-13) |
| admin | GET | `/system/audit` | `system.audit_log` | New: last 500 events |

## Appendix B: finding index

| ID | Severity | Finding | Status at `9e6e23c` |
|---|---|---|---|
| SEC-1 | Critical | Secrets in public git history | ✅ |
| SEC-2 | Critical | 15 of 26 routes unauthenticated | ✅ |
| SEC-3 | High | Debug server as entrypoint | ✅ |
| SEC-4 | High | No CSRF, destructive GETs | ✅ |
| SEC-5 | High | No authorization model | ⚠️ `LDAP_REQUIRED_GROUP_DN` default left |
| SEC-6 | High | Cleartext and unverified transport | ⚠️ LDAP left |
| SEC-7 | Medium | Secrets in logs | ✅ |
| SEC-8 | Medium | Secrets at rest | ✅ |
| SEC-9 | Medium | Session and login hardening | ⚠️ Rate limiting and headers left |
| SEC-10 | Medium | DOM-XSS sinks | ✅ |
| SEC-11 | Low | LDAP filter injection | ✅ |
| SEC-12 | Low | Supply chain and container | ✅ |
| SEC-13 | Low (new) | Config page shows `APP_DATABASE_URI` | ❌ |
| INT-1 | Critical | Revocation hits a non-existent serial | ✅ |
| INT-2 | High | Revocation status uses the wrong encoding | ✅ |
| INT-3 | Medium | Pagination ignored | ✅ |
| INT-4 | High | No TLS verification | ✅ |
| INT-5 | Medium | One shared super-admin identity | ⚠️ Dedicated ADMIN; no policy or per-user identity |
| INT-6 | Medium | Plaintext key, pointless passphrase | ✅ |
| INT-7 | Low | Hard-coded template data | ✅ |
| INT-8 | Low | Revocation reason fixed | ✅ |
| INT-9 | Medium | Coupling to step-ca's database | ⚠️ Read-only role and contract tests; no version check |
| INT-10 | Low | "Remote Provisioner" in the README | ❌ |
| BUG-1 to BUG-20 | Low to Medium | §2.3 | ✅ All fixed |
| BUG-21 | Low (new) | Flash messages lost on most pages | ❌ |
| A-1 | | Side effects at import | ⚠️ Config still read at import |
| A-2 | | Two DB stacks | ✅ |
| A-3 | | Two sources of truth for provisioners | ❌ Partly required by the Admin API |
| A-4 | | App table in step-ca's database | ✅ |
| A-5 | | No service layer | ❌ |
| A-6 | | Format knowledge spread out | ⚠️ Correct and tested, still spread out |
| A-7 | | No caching | ❌ |
| A-8 | | One shared CA identity | ⚠️ Dedicated identity, app-side audit |
| A-9 | | State in the working directory | ⚠️ Race fixed, paths still relative |
| PERF-1 | High | Quadratic certificate listing | ⚠️ O(N), dashboard still parses twice |
