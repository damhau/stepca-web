"""Certificates and revocations, against rows encoded like step-ca's tables."""

from app.services import certificates, inventory
from app.services.inventory import CertificateQuery
from app.stepca import store

SERIAL = 119960802063269571811733802872440608485  # a typical 128-bit step-ca serial


def valid_serials():
    return [item.serial for item in inventory.certificates(CertificateQuery(status="valid"), per_page=None)[0]]


def test_certificates_are_identified_by_their_decimal_serial(api, step_db):
    step_db.add_cert(SERIAL, "web.test")
    certs = store.certificates()
    assert [c.serial for c in certs] == [str(SERIAL)]
    assert certs[0].subject == "CN=web.test"
    assert certs[0].provisioner.name == "Admin JWK"
    assert [item["serial"] for item in api.get("/api/v1/certificates?status=valid").get_json()["items"]] == [str(SERIAL)]


def test_revoke_sends_the_decimal_serial_to_step_ca(api, ca_client, step_db):
    """Regression test for INT-1: the UI used to send the hex of the ASCII serial."""
    step_db.add_cert(SERIAL)
    assert api.post(f"/api/v1/certificates/{SERIAL}/revoke", json={"reason_code": 0}).status_code == 200
    ca_client.revoke.assert_called_once_with(str(SERIAL), reason_code=0, reason="Unspecified")


def test_revoke_with_a_reason(api, ca_client, step_db):
    step_db.add_cert(SERIAL)
    api.post(f"/api/v1/certificates/{SERIAL}/revoke", json={"reason_code": 4})
    ca_client.revoke.assert_called_once_with(str(SERIAL), reason_code=4, reason="Superseded")
    # Codes that make no sense for a passive revocation (certificateHold, removeFromCRL, CA compromise) are refused
    for code in (2, 6, 8, 11):
        assert api.post(f"/api/v1/certificates/{SERIAL}/revoke", json={"reason_code": code}).status_code == 422
    assert ca_client.revoke.call_count == 1


def test_revoke_of_unknown_serial_does_not_call_the_ca(api, ca_client, step_db):
    step_db.add_cert(SERIAL)
    hex_of_ascii = str(SERIAL).encode().hex()
    assert api.post(f"/api/v1/certificates/{hex_of_ascii}/revoke", json={"reason_code": 0}).status_code == 404
    ca_client.revoke.assert_not_called()


def test_revoked_certificates_are_not_valid(step_db):
    """Regression test for INT-2: revocations made by step-ca itself must be matched."""
    step_db.add_cert(SERIAL, "revoked.test")
    step_db.add_cert(42, "still-valid.test")
    step_db.add_revocation(SERIAL)
    assert valid_serials() == ["42"]
    (row,) = certificates.revoked()
    assert row.certificate.subject == "CN=revoked.test"
    assert row.provisioner_name == "Admin JWK"


def test_misdirected_revocations_are_flagged(api, step_db):
    """Revocations made by the old UI point at the hex of the ASCII serial: flag them."""
    step_db.add_cert(SERIAL, "victim.test")
    step_db.add_revocation(str(SERIAL).encode().hex())
    (row,) = certificates.revoked()
    assert row.misdirected_serial == str(SERIAL)
    assert valid_serials() == [str(SERIAL)]
    (unmatched,) = api.get("/api/v1/revocations/unmatched").get_json()["items"]
    assert unmatched["misdirected_serial"] == str(SERIAL)


def test_certificate_without_metadata_is_still_listed(api, step_db):
    step_db.add_cert(7, "no-metadata.test", provisioner=None)
    (cert,) = store.certificates()
    assert cert.subject == "CN=no-metadata.test"
    assert cert.provisioner is None
    (item,) = api.get("/api/v1/certificates").get_json()["items"]
    assert item["provisioner_name"] is None


def test_lookup_by_serial(step_db):
    step_db.add_cert(SERIAL)
    assert store.certificate(str(SERIAL)).serial == str(SERIAL)
    assert store.certificate("999") is None
    assert certificates.detail("not-a-serial") is None and not certificates.exists("not-a-serial")


def test_download_of_unknown_serial(api, step_db):
    assert api.get("/api/v1/certificates/123/download").status_code == 404
    for serial in ("abc", "1²"):
        assert api.get(f"/api/v1/certificates/{serial}/download").status_code == 422
