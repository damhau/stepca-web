import base64
import datetime
import json
import os
import re
from unittest import mock

import pytest

# config.py reads the environment at import time: set it before importing the app
os.environ.update(
    {
        "SECRET_KEY": "test-secret",
        "DATABASE_HOST": "unused",
        "DATABASE_USER": "unused",
        "DATABASE_PASSWORD": "unused",
        "DATABASE_NAME": "unused",
        "APP_DATABASE_URI": "sqlite://",
        "CA_URL": "https://ca.test:9000",
        "CA_FINGERPRINT": "00" * 32,
        "CA_ADMIN_PROVISIONER_NAME": "Admin JWK",
        "AUTH_BACKEND": "local",
    }
)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models.step import StepAdmin, StepProvisioner  # noqa: E402
from app.models.x509 import RevokedX509Cert, X509Cert, X509CertData  # noqa: E402
from config import Config  # noqa: E402

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


@pytest.fixture
def app(tmp_path, monkeypatch):
    users = tmp_path / "local_users.json"
    users.write_text(json.dumps({"admin": {"password_hash": generate_password_hash(PASSWORD)}}))

    class TestConfig(Config):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = "sqlite://"
        SQLALCHEMY_BINDS = {"app": "sqlite://"}
        LOCAL_USERS_FILE = str(users)

    # Files the app reads or writes relative to the working directory
    monkeypatch.chdir(tmp_path)
    app = create_app(TestConfig)
    with app.app_context():
        # The step-ca tables, with the same nkey/nvalue layout as step-ca's PostgreSQL tables
        db.create_all()
        yield app
        db.session.remove()


@pytest.fixture
def ca_client(monkeypatch):
    """Replaces the StepCAClient used by the blueprints: no CA is contacted in unit tests."""
    fake = mock.MagicMock()
    fake.list_provisioners.return_value = {"provisioners": [{"name": "Admin JWK", "type": "JWK", "id": ADMIN_JWK["id"]}]}
    fake.list_admins.return_value = {
        "admins": [{"id": "adm-1", "subject": "step", "provisionerId": ADMIN_JWK["id"], "type": "SUPER_ADMIN"}]
    }
    fake.revoke.return_value = {"status": "ok"}
    for module in ("app.blueprint.step.routes", "app.blueprint.x509.routes", "app.blueprint.system.routes"):
        monkeypatch.setattr(f"{module}.client", fake)
    return fake


def csrf_token(client):
    html = client.get("/auth/login").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


@pytest.fixture
def client(app, ca_client):
    """A logged-in test client."""
    client = app.test_client()
    response = client.post("/auth/login", data={"username": "admin", "password": PASSWORD, "csrf_token": csrf_token(client)})
    assert response.status_code == 302
    return client


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
                "deletedAt": "0001-01-01T00:00:00Z",
            }
            db.session.add(StepAdmin(nkey=admin_id.encode(), nvalue=json.dumps(value).encode()))
            db.session.commit()

    helper = StepDB()
    helper.add_provisioner(ADMIN_JWK["id"], ADMIN_JWK["name"])
    return helper
