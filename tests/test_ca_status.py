"""The CA's status and versions, and the certificate downloads and extensions."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.libs.cert_utils import certificate_extensions, fingerprint
from app.services import ca
from tests.conftest import CA_KEY, CA_NAME

NOW = datetime.datetime.now(datetime.UTC)


def ca_cert(name=CA_NAME, days=3650):
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(CA_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=1))
        .not_valid_after(NOW + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(CA_KEY, hashes.SHA256())
    )


def crl(*serials):
    builder = x509.CertificateRevocationListBuilder().issuer_name(CA_NAME).last_update(NOW).next_update(NOW + datetime.timedelta(days=1))
    for serial in serials:
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(NOW).build())
    return builder.sign(CA_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


INTERMEDIATE = ca_cert(days=20)


@pytest.fixture
def ca_up(ca_client, monkeypatch):
    root = ca_cert(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Root CA")]))
    ca_client.ca_url = "https://ca.test:9000"
    ca_client.health.return_value = {"status": "ok"}
    ca_client.version.return_value = {"version": "0.30.2"}
    ca_client.roots.return_value = [root]
    ca_client.intermediates.return_value = [INTERMEDIATE]
    ca_client.crl.return_value = crl(1002, 1003)
    ca_client.ca_fingerprint = fingerprint(root)
    return ca_client


@pytest.mark.parametrize("version, tested", [("0.30.2", True), ("0.30", True), ("0.31.0", False), ("0.300.1", False)])
def test_tested_versions(version, tested):
    assert ca.version_is_tested(version) is tested


def test_untested_version_is_logged(ca_up, caplog):
    ca_up.version.return_value = {"version": "0.40.0"}
    assert ca.check_ca_version(ca_up) == "0.40.0"
    assert "tested with step-ca 0.30" in caplog.text


def test_certificate_formats(api, ca_up, step_db):
    step_db.add_cert(1001, "a.test")
    der = api.get("/api/v1/certificates/1001/download?format=der")
    assert der.headers["Content-Disposition"] == 'attachment; filename="a.test.crt"'
    assert x509.load_der_x509_certificate(der.data).serial_number == 1001
    chain = x509.load_pem_x509_certificates(api.get("/api/v1/certificates/1001/download?format=chain").data)
    assert [c.subject for c in chain] == [x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "a.test")]), CA_NAME]


def test_untested_version_is_flagged(api, ca_up):
    ca_up.version.return_value = {"version": "0.31.0"}
    body = api.get("/api/v1/ca").get_json()
    assert body["version_tested"] is False and body["tested_versions"] == ["0.30"]


def test_extensions_are_readable():
    assert certificate_extensions(INTERMEDIATE) == [("Basic constraints", "CA: yes, path length 0", True)]
