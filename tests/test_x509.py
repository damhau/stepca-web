"""Certificate listing, revocation and download, against rows encoded like step-ca's tables."""

from cryptography import x509

from app.libs import db_x509
from tests.conftest import csrf_token

SERIAL = 119960802063269571811733802872440608485  # a typical 128-bit step-ca serial


def test_certificates_are_identified_by_their_decimal_serial(client, step_db):
    step_db.add_cert(SERIAL, "web.test")
    certs = db_x509.get_x509_certs()
    assert [c["nkey"] for c in certs] == [str(SERIAL)]
    assert certs[0]["data"]["subject"] == "CN=web.test"
    assert certs[0]["provisioner"]["name"] == "Admin JWK"
    assert str(SERIAL) in client.get("/x509/active").get_data(as_text=True)


def test_revoke_sends_the_decimal_serial_to_step_ca(client, ca_client, step_db):
    """Regression test for INT-1: the UI used to send the hex of the ASCII serial."""
    step_db.add_cert(SERIAL)
    response = client.post("/x509/revoke", data={"cert_id": str(SERIAL), "passphrase": "pw", "csrf_token": csrf_token(client)})
    assert response.status_code == 302
    ca_client.revoke.assert_called_once_with(str(SERIAL), "pw", reason_code=0, reason="Unspecified")
    assert response.headers["Location"].endswith(f"/x509/cert/{SERIAL}")


def test_revoke_with_a_reason(client, ca_client, step_db):
    step_db.add_cert(SERIAL)
    token = csrf_token(client)
    client.post("/x509/revoke", data={"cert_id": str(SERIAL), "passphrase": "pw", "reason": "4", "csrf_token": token})
    ca_client.revoke.assert_called_once_with(str(SERIAL), "pw", reason_code=4, reason="Superseded")
    # Codes that make no sense for a passive revocation (certificateHold, removeFromCRL, CA compromise) are refused
    for code in ("2", "6", "8", "11", "x"):
        client.post("/x509/revoke", data={"cert_id": str(SERIAL), "passphrase": "pw", "reason": code, "csrf_token": token})
    assert ca_client.revoke.call_count == 1


def test_certificate_detail_page(client, step_db):
    step_db.add_cert(SERIAL, "detail.test")
    html = client.get(f"/x509/cert/{SERIAL}").get_data(as_text=True)
    assert "CN=detail.test" in html
    assert format(SERIAL, "x") in html
    assert "Admin JWK" in html
    assert 'data-target="#revokeModal"' in html

    step_db.add_revocation(SERIAL)
    html = client.get(f"/x509/cert/{SERIAL}").get_data(as_text=True)
    assert "Revoked" in html
    assert 'data-target="#revokeModal"' not in html
    assert client.get("/x509/cert/999").status_code == 302


def test_certificate_fields_are_escaped(client, step_db):
    """Subjects come from CSRs: they must never be rendered as HTML."""
    step_db.add_cert(SERIAL, "<img src=x onerror=alert(1)>.test")
    for path in (f"/x509/cert/{SERIAL}", "/x509/active", "/x509/all"):
        html = client.get(path).get_data(as_text=True)
        assert "<img src=x" not in html, path
        assert "&lt;img src=x" in html, path


def test_revoke_of_unknown_serial_does_not_call_the_ca(client, ca_client, step_db):
    step_db.add_cert(SERIAL)
    hex_of_ascii = str(SERIAL).encode().hex()
    client.post("/x509/revoke", data={"cert_id": hex_of_ascii, "passphrase": "pw", "csrf_token": csrf_token(client)})
    ca_client.revoke.assert_not_called()


def test_revoked_certificates_are_not_active(client, step_db):
    """Regression test for INT-2: revocations made by step-ca itself must be matched."""
    step_db.add_cert(SERIAL, "revoked.test")
    step_db.add_cert(42, "still-valid.test")
    step_db.add_revocation(SERIAL)
    active = [c["nkey"] for c in db_x509.get_x509_active_certs()]
    assert active == ["42"]
    revoked = db_x509.get_revoked_x509_with_cert_info()
    assert revoked[0]["cert"]["subject"] == "CN=revoked.test"
    assert revoked[0]["data"]["provisioner_name"] == "Admin JWK"


def test_expired_and_future_certificates_are_not_active(step_db):
    import datetime

    now = datetime.datetime.now(datetime.UTC)
    step_db.add_cert(1, "expired.test", days_valid=1, not_before=now - datetime.timedelta(days=5))
    step_db.add_cert(2, "future.test", not_before=now + datetime.timedelta(days=5))
    step_db.add_cert(3, "valid.test")
    assert [c["nkey"] for c in db_x509.get_x509_active_certs()] == ["3"]


def test_misdirected_revocations_are_flagged(client, step_db):
    """Revocations made by the old UI point at the hex of the ASCII serial: flag them."""
    step_db.add_cert(SERIAL, "victim.test")
    step_db.add_revocation(str(SERIAL).encode().hex())
    revoked = db_x509.get_revoked_x509_with_cert_info()
    assert revoked[0]["data"]["misdirected_serial"] == str(SERIAL)
    assert [c["nkey"] for c in db_x509.get_x509_active_certs()] == [str(SERIAL)]
    assert f"Ineffective: certificate {SERIAL} is still valid" in client.get("/x509/revoked").get_data(as_text=True)


def test_certificate_without_metadata_is_still_listed(step_db):
    step_db.add_cert(7, "no-metadata.test", provisioner=None)
    cert = db_x509.get_x509_certs()[0]
    assert cert["data"]["subject"] == "CN=no-metadata.test"
    assert cert["provisioner"] == {}


def test_lookup_by_id(step_db):
    step_db.add_cert(SERIAL)
    assert db_x509.get_x509_certs_by_id(str(SERIAL))["nkey"] == str(SERIAL)
    assert db_x509.get_x509_certs_by_id("999") is None
    assert db_x509.get_x509_certs_by_id("not-a-serial") is None


def test_download_returns_the_stored_certificate(client, step_db):
    step_db.add_cert(SERIAL, "dl.test")
    response = client.get(f"/x509/download/{SERIAL}")
    assert response.status_code == 200
    assert 'filename="dl.test.pem"' in response.headers["Content-Disposition"]
    assert x509.load_pem_x509_certificate(response.data).serial_number == SERIAL


def test_download_of_unknown_serial_redirects(client, step_db):
    for serial in ("123", "abc", "1²"):
        response = client.get(f"/x509/download/{serial}")
        assert response.status_code == 302


def test_api_returns_one_certificate(client, step_db):
    step_db.add_cert(SERIAL, "api.test")
    data = client.get(f"/api/x509/certs/{SERIAL}").get_json()
    assert data["nkey"] == str(SERIAL)
    assert client.get("/api/x509/certs/999").status_code == 404
