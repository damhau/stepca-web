"""app.stepca.store: step-ca's tables, read into records."""

import datetime

from app.extensions import db
from app.models.x509 import X509Cert
from app.services import provisioners
from app.stepca import store


def test_provisioners_with_their_type_name_and_without_deleted_ones(step_db):
    step_db.add_provisioner("prov-acme", "acme", prov_type=6)
    step_db.add_provisioner("prov-old", "old", deleted=True)
    assert {(p.name, p.type) for p in store.provisioners()} == {("Admin JWK", "JWK"), ("acme", "ACME")}
    assert "old" in {p.name for p in store.provisioners(include_deleted=True)}
    assert provisioners.names_by_id() == {"prov-admin-jwk": "Admin JWK", "prov-acme": "acme"}
    assert provisioners.signing_provisioners() == ["Admin JWK"]


def test_admins(step_db):
    step_db.add_admin("adm-1", "alice", "prov-admin-jwk", admin_type=1)
    (admin,) = store.admins()
    assert (admin.subject, admin.type, admin.deleted) == ("alice", "ADMIN", False)
    assert admin.created_at == datetime.datetime(2026, 10, 29, 12, 30, 8, tzinfo=datetime.UTC)


def test_revocation_fields(step_db):
    step_db.add_cert(1002, "r.test")
    step_db.add_revocation(1002)
    revocation = store.revocation("1002")
    assert (revocation.serial, revocation.reason_code, revocation.provisioner_id) == ("1002", 1, "prov-admin-jwk")
    assert revocation.revoked_at == datetime.datetime(2026, 10, 28, 12, tzinfo=datetime.UTC)
    assert store.revoked_serials() == {"1002"}
    assert store.revocation("1") is None


def test_a_certificate_that_does_not_parse_is_kept_with_its_error(step_db):
    db.session.add(X509Cert(nkey=b"77", nvalue=b"not DER"))
    db.session.commit()
    (cert,) = store.certificates()
    assert cert.serial == "77" and cert.error and cert.subject == "[error decoding cert]"


def test_certificates_by_serial(step_db):
    step_db.add_cert(1, "a.test")
    step_db.add_cert(2, "b.test")
    assert [c.serial for c in store.certificates(["2"])] == ["2"]
    assert store.certificates([]) == []
    assert store.certificate_count() == 2
