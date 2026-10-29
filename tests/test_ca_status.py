"""The CA status page, the CA's downloads and the certificate page's formats and extensions."""

import datetime

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from app.libs import ca
from app.libs.cert_utils import certificate_extensions, fingerprint
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
    monkeypatch.setattr(ca, "CA_FINGERPRINT", fingerprint(root))
    return ca_client


@pytest.mark.parametrize("version, tested", [("0.30.2", True), ("0.30", True), ("0.31.0", False), ("0.300.1", False)])
def test_tested_versions(version, tested):
    assert ca.version_is_tested(version) is tested


def test_untested_version_is_logged(ca_up, caplog):
    ca_up.version.return_value = {"version": "0.40.0"}
    assert ca.check_ca_version() == "0.40.0"
    assert "tested with step-ca 0.30" in caplog.text


def test_status_page(client, ca_up):
    html = client.get("/step/ca").get_data(as_text=True)
    assert "0.30.2" in html and "not tested" not in html
    assert "badge-success\">ok" in html
    assert "pinned" in html and fingerprint(ca_up.roots.return_value[0]) in html
    # The intermediate expires in 20 days
    assert "badge-danger\">19 days left" in html or "badge-danger\">20 days left" in html
    assert "<th class=\"w-25\">Revoked certificates</th><td>2</td>" in html


def test_status_page_with_the_ca_down(client, ca_up):
    for call in (ca_up.health, ca_up.version, ca_up.roots, ca_up.intermediates, ca_up.crl):
        call.side_effect = requests.ConnectionError("connection refused")
    response = client.get("/step/ca")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "unreachable" in html and "Could not read version: connection refused" in html


def test_status_page_without_crl(client, ca_up):
    ca_up.crl.return_value = None
    assert '"crl": {"enabled": true}' in client.get("/step/ca").get_data(as_text=True)


def test_untested_version_is_flagged(client, ca_up):
    ca_up.version.return_value = {"version": "0.31.0"}
    assert "not tested" in client.get("/step/ca").get_data(as_text=True)


def test_ca_downloads(client, ca_up):
    roots = client.get("/step/ca/roots.pem")
    assert roots.headers["Content-Disposition"] == 'attachment; filename="roots.pem"'
    assert x509.load_pem_x509_certificates(roots.data) == ca_up.roots.return_value
    assert x509.load_der_x509_crl(client.get("/step/ca/crl").data).get_revoked_certificate_by_serial_number(1002)
    assert len(x509.load_pem_x509_crl(client.get("/step/ca/crl?pem").data)) == 2
    assert client.get("/step/ca/other.pem").status_code == 404


def test_certificate_formats(client, ca_up, step_db):
    step_db.add_cert(1001, "a.test")
    der = client.get("/x509/download/1001?format=der")
    assert der.headers["Content-Disposition"] == 'attachment; filename="a.test.crt"'
    assert x509.load_der_x509_certificate(der.data).serial_number == 1001
    chain = x509.load_pem_x509_certificates(client.get("/x509/download/1001?format=chain").data)
    assert [c.subject for c in chain] == [x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "a.test")]), CA_NAME]


def test_chain_download_with_the_ca_down(client, ca_up, step_db):
    step_db.add_cert(1001, "a.test")
    ca_up.intermediates.side_effect = requests.ConnectionError("connection refused")
    response = client.get("/x509/download/1001?format=chain", follow_redirects=True)
    assert "Could not load the intermediate certificates from the CA" in response.get_data(as_text=True)


def test_certificate_page_lists_extensions(client, step_db):
    step_db.add_cert(1001, "a.test")
    html = client.get("/x509/cert/1001").get_data(as_text=True)
    assert "Subject alternative names" in html and "DNS:a.test" in html


def test_extensions_are_readable():
    assert certificate_extensions(INTERMEDIATE) == [("Basic constraints", "CA: yes, path length 0", True)]
