import base64
import datetime
import json
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from flask import g
from werkzeug.security import generate_password_hash

from app import create_app
from app.extensions import db
from app.models import acme as acme_tables
from app.models.step import StepAdmin, StepProvisioner
from app.models.x509 import RevokedX509Cert, X509Cert, X509CertData
from app.settings import Settings

PASSWORD = "testpw"
ADMIN_JWK = {"id": "prov-admin-jwk", "name": "Admin JWK", "type": "JWK"}
CA_KEY = ec.generate_private_key(ec.SECP256R1())
CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])


def make_cert(serial, common_name, days_valid=30, not_before=None):
    """A leaf certificate signed by the test CA, as DER (the format step-ca stores)."""
    not_before = not_before or datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(CA_NAME)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(CA_KEY, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


CA_URL = "https://ca.test:9000"


class IsolatedSettings(Settings):
    """Settings from the test's arguments only: neither the environment nor a settings.json."""

    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings):
        return (init_settings,)


def make_settings(data_dir, **overrides):
    values = {
        "data_dir": data_dir,
        "testing": True,
        "secret_key": "test-secret",
        "database_host": "unused",
        "database_user": "unused",
        "database_password": "unused",
        "database_name": "unused",
        "sqlalchemy_database_uri": "sqlite://",
        "app_database_uri": "sqlite://",
        "ca_url": CA_URL,
        "ca_fingerprint": "00" * 32,
        "ca_admin_provisioner_name": "Admin JWK",
        "auth_backend": "local",
        # Every read sees the rows the test just added
        "inventory_refresh_seconds": 0,
    }
    return IsolatedSettings(**{**values, **overrides})


# What `npm run build` writes to frontend/dist, in miniature
INDEX_HTML = """<!doctype html><html><head><meta name="csp-nonce" content="__CSP_NONCE__" />
<script type="module" crossorigin src="/assets/index-abc123.js"></script></head><body><div id="root"></div></body></html>"""


@pytest.fixture
def app(tmp_path, monkeypatch):
    frontend = tmp_path / "dist"
    (frontend / "assets").mkdir(parents=True)
    (frontend / "index.html").write_text(INDEX_HTML)
    (frontend / "assets" / "index-abc123.js").write_text("console.log('app')")
    (frontend / "theme.js").write_text("// theme")
    users = tmp_path / "local_users.json"
    password_hash = generate_password_hash(PASSWORD)
    users.write_text(json.dumps({role: {"password_hash": password_hash, "role": role} for role in ("viewer", "operator", "admin")}))
    # Nothing may depend on the working directory: every file is in the data directory
    monkeypatch.chdir("/")
    app = create_app(make_settings(tmp_path, frontend_dir=frontend))

    # The app context below stays pushed for the whole test, so `g` outlives each request (unlike in
    # production). Reset Flask-WTF's per-request token cache, or a token cleared at login would be reused.
    @app.before_request
    def fresh_csrf_cache():
        g.pop("csrf_token", None)

    with app.app_context():
        # The step-ca tables, with the same nkey/nvalue layout as step-ca's PostgreSQL tables
        db.create_all()
        yield app
        db.session.remove()


@pytest.fixture
def ca_client(app, monkeypatch):
    """Replaces the app's StepCAClient: no CA is contacted in unit tests."""
    fake = mock.MagicMock()
    fake.list_provisioners.return_value = {"provisioners": [{"name": "Admin JWK", "type": "JWK", "id": ADMIN_JWK["id"]}]}
    fake.list_admins.return_value = {"admins": [{"id": "adm-1", "subject": "step", "provisioner_id": ADMIN_JWK["id"], "type": 2}]}
    fake.revoke.return_value = {"status": "ok"}
    fake.admin_key_source.return_value = "encrypted key from the CA, decrypted in memory"
    fake.ca_url = CA_URL
    fake.ca_fingerprint = "00" * 32
    fake.subject = "step"
    fake.provisioner_name = "Admin JWK"
    app.extensions["stepca"] = fake
    # The app's identity on the CA; tests change it with fake.identity = "ADMIN"
    fake.identity = "SUPER_ADMIN"
    monkeypatch.setattr("app.services.provisioners.identity_type", lambda: fake.identity)
    return fake


@pytest.fixture
def step_db(app):
    """Helpers to put rows in the step-ca tables, encoded the way step-ca writes them."""

    class StepDB:
        def add_cert(self, serial, common_name="host.test", provisioner=ADMIN_JWK, **kwargs):
            key = str(serial).encode()
            db.session.add(X509Cert(nkey=key, nvalue=make_cert(serial, common_name, **kwargs)))
            if provisioner is not None:
                db.session.add(X509CertData(nkey=key, nvalue=json.dumps({"provisioner": provisioner}).encode()))
            db.session.commit()
            return str(serial)

        def add_revocation(self, serial, provisioner_id=ADMIN_JWK["id"]):
            info = {"Serial": str(serial), "ProvisionerID": provisioner_id, "ReasonCode": 1, "RevokedAt": "2026-10-28T12:00:00Z"}
            db.session.add(RevokedX509Cert(nkey=str(serial).encode(), nvalue=json.dumps(info).encode()))
            db.session.commit()

        def add_provisioner(self, prov_id, name, prov_type=1, deleted=False):
            details = base64.b64encode(json.dumps({"Data": {}}).encode()).decode()
            value = {
                "id": prov_id,
                "name": name,
                "type": prov_type,
                "details": details,
                "deletedAt": "2026-01-01T00:00:00Z" if deleted else "0001-01-01T00:00:00Z",
            }
            db.session.add(StepProvisioner(nkey=prov_id.encode(), nvalue=json.dumps(value).encode()))
            db.session.commit()

        def add_admin(self, admin_id, subject, provisioner_id, admin_type=2):
            value = {
                "id": admin_id,
                "subject": subject,
                "provisionerID": provisioner_id,
                "type": admin_type,
                "createdAt": "2026-10-29T12:30:08Z",
                "deletedAt": "0001-01-01T00:00:00Z",
            }
            db.session.add(StepAdmin(nkey=admin_id.encode(), nvalue=json.dumps(value).encode()))
            db.session.commit()

        def add_acme_issuance(self, serial, common_name, prefix="a"):
            """An ACME account, its valid order, authorization, 3 challenges (http-01 valid) and certificate,
            as step-ca stores them. Returns the ids."""
            ids = {kind: f"{prefix}-{kind}" for kind in ("account", "order", "authz", "cert")}
            challenges = [f"{prefix}-challenge-{kind}" for kind in ("dns", "http", "tls")]
            when = "2026-10-29T14:28:37Z"
            pem = x509.load_der_x509_certificate(make_cert(serial, common_name)).public_bytes(serialization.Encoding.PEM)
            rows = [
                (acme_tables.AcmeAccount, ids["account"], {
                    "id": ids["account"], "key": {"kty": "EC"}, "contact": ["ops@example.org"], "status": "valid",
                    "provisionerID": "prov-acme", "provisionerName": "acme", "createdAt": when, "deactivatedAt": "0001-01-01T00:00:00Z",
                }),
                (acme_tables.AcmeOrder, ids["order"], {
                    "id": ids["order"], "accountID": ids["account"], "provisionerID": "prov-acme",
                    "identifiers": [{"type": "dns", "value": common_name}], "authorizationIDs": [ids["authz"]], "status": "valid",
                    "notBefore": when, "notAfter": "2026-10-30T14:28:37Z", "createdAt": when, "expiresAt": "2026-10-30T14:28:37Z",
                    "certificate": ids["cert"],
                }),
                (acme_tables.AcmeAuthz, ids["authz"], {
                    "id": ids["authz"], "accountID": ids["account"], "identifier": {"type": "dns", "value": common_name},
                    "status": "valid", "token": "t", "challengeIDs": challenges, "wildcard": False,
                    "createdAt": when, "expiresAt": "2026-10-30T14:28:37Z", "error": None,
                }),
                (acme_tables.AcmeCert, ids["cert"], {
                    "id": ids["cert"], "createdAt": "2026-10-29T14:28:39.777624623Z", "accountID": ids["account"],
                    "orderID": ids["order"], "leaf": base64.b64encode(pem).decode(), "intermediates": "",
                }),
                (acme_tables.AcmeSerialCert, str(serial), {"serial": str(serial), "certificateID": ids["cert"]}),
            ]
            for challenge_id, kind in zip(challenges, ("dns-01", "http-01", "tls-alpn-01"), strict=True):
                valid = kind == "http-01"
                rows.append((acme_tables.AcmeChallenge, challenge_id, {
                    "id": challenge_id, "accountID": ids["account"], "type": kind, "status": "valid" if valid else "pending",
                    "token": "t", "value": common_name, "validatedAt": "2026-10-29T14:28:38Z" if valid else "",
                    "createdAt": when, "error": None,
                }))
            for model, key, value in rows:
                db.session.add(model(nkey=key.encode(), nvalue=json.dumps(value).encode()))
            db.session.commit()
            return ids

    helper = StepDB()
    helper.add_provisioner(ADMIN_JWK["id"], ADMIN_JWK["name"])
    return helper


class ApiClient:
    """A test client of the JSON API: signs in through it and sends the CSRF token as the frontend does."""

    def __init__(self, app, role=None):
        self.client = app.test_client()
        self.token = self.client.get("/api/v1/session").get_json()["csrf_token"]
        if role:
            response = self.post("/api/v1/session", json={"username": role, "password": PASSWORD})
            assert response.status_code == 200, response.get_json()
            # Signing in starts a new session, with a new token
            self.token = response.get_json()["csrf_token"]

    def get(self, path, **kwargs):
        return self.client.get(path, **kwargs)

    def _send(self, method, path, **kwargs):
        headers = {"X-CSRFToken": self.token, **kwargs.pop("headers", {})}
        return self.client.open(path, method=method, headers=headers, **kwargs)

    def post(self, path, **kwargs):
        return self._send("POST", path, **kwargs)

    def put(self, path, **kwargs):
        return self._send("PUT", path, **kwargs)

    def patch(self, path, **kwargs):
        return self._send("PATCH", path, **kwargs)

    def delete(self, path, **kwargs):
        return self._send("DELETE", path, **kwargs)


@pytest.fixture
def api(app, ca_client):
    """The API, signed in as an admin."""
    return ApiClient(app, "admin")


@pytest.fixture
def api_as(app, ca_client):
    """The API signed in with a given role: api_as("viewer")."""
    return lambda role: ApiClient(app, role)
