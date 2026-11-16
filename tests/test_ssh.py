"""SSH certificates, against rows encoded like step-ca's ssh_certs table: the OpenSSH wire format keyed by decimal serial."""

import base64
import datetime
import hashlib
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, ssh

from app.extensions import db
from app.libs import ssh_cert
from app.models.ssh import RevokedSshCert
from app.stepca import store
from tests.conftest import FOREVER, SSH_CA_KEY, make_ssh_cert

SERIAL = 7016279347203646317  # a typical 64-bit step-ca SSH serial
HOUR = 3600


def now():
    return int(datetime.datetime.now(datetime.UTC).timestamp())


def listed(api, query=""):
    return api.get(f"/api/v1/ssh/certificates{query}").get_json()


def fingerprint_of(public_key):
    blob = base64.b64decode(public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# --- Reading the wire format ------------------------------------------------------------------------------


def test_a_user_certificate_is_read_from_the_wire_format():
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    blob = make_ssh_cert(SERIAL, "alice@example.org", ("alice", "root"), valid_after=1_700_000_000, valid_before=1_700_057_600, key=key)
    info = ssh_cert.parse(blob)
    assert (info.kind, info.key_id, info.principals) == ("user", "alice@example.org", ["alice", "root"])
    assert info.valid_after == datetime.datetime(2023, 11, 14, 22, 13, 20, tzinfo=datetime.UTC)
    assert info.valid_before - info.valid_after == datetime.timedelta(hours=16)
    assert info.key_type == "ECDSA nistp256"
    # The fingerprints are the ones ssh-keygen -l prints: of the certified key, and of the CA's
    assert info.fingerprint == fingerprint_of(key)
    assert info.ca_fingerprint == fingerprint_of(SSH_CA_KEY.public_key())
    assert info.ca_key_type == "ED25519"


def test_key_types():
    assert ssh_cert.parse(make_ssh_cert(1)).key_type == "ED25519"
    assert ssh_cert.parse(make_ssh_cert(2, key=rsa.generate_private_key(65537, 3072).public_key())).key_type == "RSA 3072"
    assert ssh_cert.parse(make_ssh_cert(3, key=ec.generate_private_key(ec.SECP384R1()).public_key())).key_type == "ECDSA nistp384"


def test_a_host_certificate_that_never_expires():
    info = ssh_cert.parse(make_ssh_cert(SERIAL, "web-1", ("web-1.example.org", "web-1"), kind="host", valid_after=0, valid_before=FOREVER))
    assert info.kind == "host"
    assert (info.valid_after, info.valid_before) == (None, None)


def test_critical_options_and_extensions():
    info = ssh_cert.parse(
        make_ssh_cert(SERIAL, options={"force-command": "/usr/bin/uptime", "source-address": "10.0.0.0/8"}, extensions={"permit-pty": ""})
    )
    assert info.critical_options == {"force-command": "/usr/bin/uptime", "source-address": "10.0.0.0/8"}
    assert info.extensions == {"permit-pty": ""}


def test_what_is_not_a_certificate_is_an_error_not_a_crash(step_db, api):
    plain_key = ssh.load_ssh_public_key(
        ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    ).public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    for blob in (b"", b"\x00\x00\x00\x03abc", base64.b64decode(plain_key.split()[1])):
        try:
            ssh_cert.parse(blob)
        except ValueError:
            continue
        raise AssertionError(f"{blob!r} was read as a certificate")
    step_db.add_raw_ssh_cert(11, b"\x00\x00\x00\x03abc")
    step_db.add_ssh_cert(12, "fine@example.org")
    items = {item["serial"]: item for item in listed(api)["items"]}
    assert items["11"]["status"] == "invalid" and items["11"]["error"]
    assert items["12"]["status"] == "valid" and items["12"]["error"] is None


def test_a_key_type_cryptography_cannot_read_is_named(step_db, api):
    """Security-key certificates (sk-ssh-ed25519-cert-v01@openssh.com) are stored all the same: say which type it is."""
    kind = b"sk-ssh-ed25519-cert-v01@openssh.com"
    step_db.add_raw_ssh_cert(21, len(kind).to_bytes(4, "big") + kind + b"\x00" * 16)
    item = listed(api)["items"][0]
    assert item["status"] == "invalid"
    assert "sk-ssh-ed25519-cert-v01@openssh.com" in item["error"]
    # ... and the file can still be downloaded, to look at with ssh-keygen -L
    assert api.get("/api/v1/ssh/certificates/21/download").status_code == 200


# --- The list ---------------------------------------------------------------------------------------------


def test_the_list_has_user_and_host_certificates_newest_first(step_db, api):
    step_db.add_ssh_cert(1, "old@example.org", valid_after=now() - 5 * HOUR)
    step_db.add_ssh_cert(2, "web-1", ("web-1.example.org",), kind="host", valid_after=now() - HOUR)
    step_db.add_ssh_cert(3, "new@example.org", valid_after=now() - 60)
    body = listed(api)
    assert body["total"] == 3
    assert [(item["serial"], item["kind"]) for item in body["items"]] == [("3", "user"), ("2", "host"), ("1", "user")]
    item = body["items"][1]
    assert item["key_id"] == "web-1" and item["principals"] == ["web-1.example.org"]
    assert item["key_type"] == "ED25519" and item["fingerprint"].startswith("SHA256:")


def test_status_follows_validity_and_revocations(step_db, api):
    step_db.add_ssh_cert(1, "valid")
    step_db.add_ssh_cert(2, "expired", valid_after=now() - 10 * HOUR, valid_before=now() - HOUR)
    step_db.add_ssh_cert(3, "later", valid_after=now() + HOUR, valid_before=now() + 5 * HOUR)
    step_db.add_ssh_cert(4, "revoked")
    step_db.add_ssh_revocation(4)
    step_db.add_ssh_cert(5, "forever", kind="host", valid_after=0, valid_before=FOREVER)
    status = {item["key_id"]: item["status"] for item in listed(api)["items"]}
    assert status == {"valid": "valid", "expired": "expired", "later": "not_yet_valid", "revoked": "revoked", "forever": "valid"}
    revoked = listed(api, "?status=revoked")["items"][0]
    assert revoked["revocation_reason"] == "key compromise" and revoked["revoked_at"].startswith("2026-10-28")


def test_filters(step_db, api):
    step_db.add_ssh_cert(1, "alice@example.org", ("alice", "deploy"))
    step_db.add_ssh_cert(2, "bob@example.org", ("bob",))
    step_db.add_ssh_cert(SERIAL, "db-1", ("db-1.example.org",), kind="host")
    step_db.add_ssh_cert(4, "gone", ("gone",), valid_after=now() - 9 * HOUR, valid_before=now() - HOUR)

    def serials(query):
        return sorted(item["serial"] for item in listed(api, query)["items"])

    assert serials("?kind=user") == ["1", "2", "4"]
    assert serials("?kind=host") == [str(SERIAL)]
    assert serials("?status=expired") == ["4"]
    assert serials("?kind=user&status=valid") == ["1", "2"]
    # The text filter looks at the serial, the key id, the principals and the fingerprint, whatever the case.
    # (Fingerprints are random base64: the terms below can't be in one by chance, and a single digit could.)
    assert serials("?q=DEPLOY") == ["1"]
    assert serials("?q=db-1.example") == [str(SERIAL)]
    assert serials(f"?q={str(SERIAL)[:12]}") == [str(SERIAL)]
    fingerprint = listed(api, "?q=bob@example")["items"][0]["fingerprint"]
    # Base64 has + and /: quoted, as the frontend's URLSearchParams does, or a + is read as a space
    assert serials(f"?q={quote(fingerprint.removeprefix('SHA256:')[:12], safe='')}") == ["2"]
    assert serials("?q=nobody") == []


def test_an_unknown_filter_value_is_refused(api):
    assert api.get("/api/v1/ssh/certificates?kind=robot").status_code == 422
    assert api.get("/api/v1/ssh/certificates?status=bogus").status_code == 422
    assert api.get("/api/v1/ssh/certificates?sort=nothing").status_code == 422


def test_sorting_and_paging(step_db, api):
    for serial, key_id, until in ((10, "carol", 4), (2, "alice", 8), (300, "bob", 2)):
        step_db.add_ssh_cert(serial, key_id, valid_before=now() + until * HOUR)
    step_db.add_ssh_cert(4, "never", kind="host", valid_after=0, valid_before=FOREVER)

    def order(query):
        return [item["key_id"] for item in listed(api, query)["items"]]

    assert order("?sort=key_id&order=asc") == ["alice", "bob", "carol", "never"]
    # By number, not as text: 300 after 10
    assert [item["serial"] for item in listed(api, "?sort=serial&order=asc")["items"]] == ["2", "4", "10", "300"]
    # A certificate that never expires comes after every other when sorted by expiry
    assert order("?sort=valid_before&order=asc") == ["bob", "carol", "alice", "never"]
    page = listed(api, "?sort=serial&order=asc&per_page=2&page=2")
    assert (page["total"], page["page"], [item["serial"] for item in page["items"]]) == (4, 2, ["10", "300"])


def test_counts(step_db, api):
    step_db.add_ssh_cert(1)
    step_db.add_ssh_cert(2, kind="host")
    step_db.add_ssh_cert(3, valid_after=now() - 9 * HOUR, valid_before=now() - HOUR)
    step_db.add_ssh_cert(4)
    step_db.add_ssh_revocation(4)
    step_db.add_ssh_cert(5, valid_after=now() + HOUR, valid_before=now() + 5 * HOUR)
    step_db.add_raw_ssh_cert(6, b"\x00\x00\x00\x03abc")
    # Certificates that aren't valid yet, or can't be read, are only in "all"
    assert api.get("/api/v1/ssh/certificates/counts").get_json() == {"all": 6, "valid": 2, "expired": 1, "revoked": 1}


def test_counts_of_one_kind(step_db, api):
    """The tabs' counts follow the user/host filter, so they match the list under it."""
    step_db.add_ssh_cert(1)
    step_db.add_ssh_cert(2, kind="host")
    step_db.add_ssh_cert(3, kind="host", valid_after=now() - 9 * HOUR, valid_before=now() - HOUR)
    step_db.add_ssh_cert(4, kind="host")
    step_db.add_ssh_revocation(4)
    assert api.get("/api/v1/ssh/certificates/counts?kind=host").get_json() == {"all": 3, "valid": 1, "expired": 1, "revoked": 1}
    assert api.get("/api/v1/ssh/certificates/counts?kind=user").get_json() == {"all": 1, "valid": 1, "expired": 0, "revoked": 0}
    assert api.get("/api/v1/ssh/certificates/counts?kind=robot").status_code == 422


def test_csv_export_has_every_match_not_one_page(step_db, api):
    for serial in range(1, 6):
        step_db.add_ssh_cert(serial, f"user{serial}@example.org", ("a", "b"))
    step_db.add_ssh_cert(6, "=cmd|' /C calc'!A0", ("x",))
    response = api.get("/api/v1/ssh/certificates?format=csv&per_page=2&sort=serial&order=asc")
    assert response.headers["Content-Disposition"] == 'attachment; filename="ssh-certificates.csv"'
    lines = response.get_data(as_text=True).splitlines()
    assert lines[0].startswith("serial,kind,key_id,principals,status")
    assert len(lines) == 7
    assert lines[1].startswith("1,user,user1@example.org,a b,valid")
    # A key id is chosen by whoever asked for the certificate: it must not become a spreadsheet formula
    assert ",'=cmd" in lines[6]


def test_without_the_revocations_table_the_list_still_works(step_db, api):
    step_db.add_ssh_cert(1)
    db.session.execute(db.text("DROP TABLE revoked_ssh_certs"))
    db.session.commit()
    assert store.ssh_revocations() == {}
    assert [item["status"] for item in listed(api)["items"]] == ["valid"]
    RevokedSshCert.__table__.create(db.engine)  # as it was, for the other tests' teardown


# --- One certificate ----------------------------------------------------------------------------------------


def test_a_certificates_page(step_db, api):
    step_db.add_ssh_cert(
        SERIAL, "alice@example.org", ("alice", "root"), options={"force-command": "/usr/bin/uptime"}, extensions={"permit-pty": "", "permit-agent-forwarding": ""}
    )
    found = api.get(f"/api/v1/ssh/certificates/{SERIAL}").get_json()
    assert found["certificate"]["serial"] == str(SERIAL)
    assert found["certificate"]["principals"] == ["alice", "root"]
    assert found["critical_options"] == [{"name": "force-command", "value": "/usr/bin/uptime"}]
    assert [extension["name"] for extension in found["extensions"]] == ["permit-agent-forwarding", "permit-pty"]
    assert found["revocation"] is None
    # The line is a certificate OpenSSH reads: it parses back to the same one
    again = ssh.load_ssh_public_identity(found["public_line"].encode())
    assert again.serial == SERIAL and again.key_id == b"alice@example.org"


def test_a_revoked_certificates_page_says_who_and_why(step_db, api):
    step_db.add_ssh_cert(SERIAL)
    step_db.add_ssh_revocation(SERIAL)
    found = api.get(f"/api/v1/ssh/certificates/{SERIAL}").get_json()
    assert found["certificate"]["status"] == "revoked"
    assert found["revocation"]["reason"] == "key compromise"
    assert found["revocation"]["provisioner_name"] == "Admin JWK"


def test_unknown_and_malformed_serials(step_db, api):
    step_db.add_ssh_cert(SERIAL)
    assert api.get("/api/v1/ssh/certificates/12345").status_code == 404
    assert api.get("/api/v1/ssh/certificates/12345/download").status_code == 404
    # Not a decimal serial: refused before the database is asked
    assert api.get("/api/v1/ssh/certificates/abc").status_code == 422
    assert api.get("/api/v1/ssh/certificates/1%27%20OR%20%271").status_code in (404, 422)


def test_an_x509_serial_is_not_an_ssh_certificate(step_db, api):
    """The two kinds of certificate have their own tables: the same serial in one doesn't show in the other."""
    step_db.add_cert(99, "web.test")
    assert api.get("/api/v1/ssh/certificates/99").status_code == 404
    step_db.add_ssh_cert(98)
    assert api.get("/api/v1/certificates/98").status_code == 404


def test_download_is_the_cert_pub_file(step_db, api):
    step_db.add_ssh_cert(SERIAL, "../../etc/passwd alice@example.org")
    response = api.get(f"/api/v1/ssh/certificates/{SERIAL}/download")
    assert response.status_code == 200
    # The key id is chosen by whoever asked for the certificate: it can't escape the file name
    assert response.headers["Content-Disposition"] == 'attachment; filename=".._.._etc_passwd_alice_example.org-cert.pub"'
    line = response.get_data(as_text=True)
    assert line.startswith("ssh-ed25519-cert-v01@openssh.com AAAA") and line.endswith("\n") and line.count("\n") == 1
    assert ssh.load_ssh_public_identity(line.encode()).serial == SERIAL


def test_serials_above_2_to_the_63_as_step_ca_writes_them(step_db, api):
    """step-ca's SSH serials are random 64-bit numbers, so half of them don't fit a signed integer (these are from a real CA)."""
    serials = [354557403583350852, 10869767116135527849, 14985688752270048630]
    for serial in serials:
        step_db.add_ssh_cert(serial, f"host-{serial}", kind="host")
    # Sorted by number, not as text (as text, 1086... would come before 3545...)
    ordered = listed(api, "?sort=serial&order=asc")["items"]
    assert [item["serial"] for item in ordered] == [str(serial) for serial in sorted(serials)]
    biggest = max(serials)
    assert api.get(f"/api/v1/ssh/certificates/{biggest}").get_json()["certificate"]["serial"] == str(biggest)
    line = api.get(f"/api/v1/ssh/certificates/{biggest}/download").get_data(as_text=True)
    assert ssh.load_ssh_public_identity(line.encode()).serial == biggest
    assert [item["serial"] for item in listed(api, f"?q={biggest}")["items"]] == [str(biggest)]


def test_certificates_signed_by_an_ecdsa_ca(step_db, api):
    """step-ca's SSH CA is usually ECDSA P-256, whatever the keys it certifies: a user's ECDSA key and a host's Ed25519 key."""
    ca = ec.generate_private_key(ec.SECP256R1())
    user_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    step_db.add_ssh_cert(1, "alice@example.com", ("alice", "alice@example.com"), key=user_key, ca_key=ca)
    step_db.add_ssh_cert(2, "host-01.example.com", ("host-01", "host-01.example.com"), kind="host", ca_key=ca)
    items = {item["serial"]: item for item in listed(api, "?sort=serial&order=asc")["items"]}
    assert (items["1"]["kind"], items["1"]["key_type"]) == ("user", "ECDSA nistp256")
    assert (items["2"]["kind"], items["2"]["key_type"]) == ("host", "ED25519")
    assert items["1"]["ca_fingerprint"] == items["2"]["ca_fingerprint"] == fingerprint_of(ca.public_key())


def test_a_revocation_that_is_not_a_json_object_still_counts_as_revoked(step_db):
    step_db.add_ssh_cert(SERIAL)
    db.session.add(RevokedSshCert(nkey=str(SERIAL).encode(), nvalue=b"null"))
    db.session.commit()
    assert store.ssh_revocations()[str(SERIAL)].serial == str(SERIAL)
