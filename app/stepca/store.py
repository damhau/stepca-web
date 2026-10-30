"""Reads step-ca's database. step-ca keeps each kind of object in a key/value table (nkey, nvalue): for
certificates the key is the decimal serial and the value the DER; otherwise the value is the JSON of a Go
struct (db/db.go, acme/db/nosql and authority/admin/db/nosql in step-ca). This module is the only place
that knows those tables and field names; it returns records.py dataclasses."""

import json
import logging
from datetime import datetime

from cryptography import x509

from app.extensions import db
from app.libs.cert_utils import key_description, load_certificate, parse_cert
from app.models import acme as tables
from app.models import step as step_tables
from app.models import x509 as x509_tables
from app.stepca.records import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeIdentifier,
    AcmeOrder,
    Admin,
    Certificate,
    Provisioner,
    ProvisionerRef,
    Revocation,
)

log = logging.getLogger(__name__)


def go_time(value):
    """A Go time.Time from JSON, or None for Go's zero time (step-ca's "never") and empty strings."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return None if parsed.year == 1 else parsed


def acme_error(value):
    """The detail of an acme.Error, or None."""
    if not value:
        return None
    return value.get("detail") or value.get("type") or "error"


def _rows(model, keys=None):
    """(key, decoded JSON) of the rows of a table, or of the rows with these keys. Rows that don't parse are logged and skipped."""
    query = db.session.query(model)
    if keys is not None:
        query = query.filter(model.nkey.in_([key.encode() for key in keys]))
    for row in query.all():
        try:
            yield bytes(row.nkey).decode(), json.loads(bytes(row.nvalue))
        except (ValueError, UnicodeDecodeError) as e:
            log.warning("Cannot parse a row of %s: %s", model.__tablename__, e)


def _row(model, key):
    row = db.session.get(model, key.encode())
    if row is None:
        return None
    try:
        return json.loads(bytes(row.nvalue))
    except ValueError as e:
        log.warning("Cannot parse %s %s: %s", model.__tablename__, key, e)
        return None


def _identifier(value):
    value = value or {}
    return AcmeIdentifier(type=value.get("type", ""), value=value.get("value", ""))


def _account(data):
    return AcmeAccount(
        id=data["id"],
        status=data.get("status", ""),
        contact=data.get("contact") or [],
        provisioner_id=data.get("provisionerID") or None,
        provisioner_name=data.get("provisionerName") or None,
        created_at=go_time(data.get("createdAt")),
        deactivated_at=go_time(data.get("deactivatedAt")),
    )


def _order(data):
    return AcmeOrder(
        id=data["id"],
        account_id=data.get("accountID", ""),
        provisioner_id=data.get("provisionerID") or None,
        identifiers=[_identifier(i) for i in data.get("identifiers") or []],
        authorization_ids=data.get("authorizationIDs") or [],
        status=data.get("status", ""),
        certificate_id=data.get("certificate") or None,
        not_before=go_time(data.get("notBefore")),
        not_after=go_time(data.get("notAfter")),
        created_at=go_time(data.get("createdAt")),
        expires_at=go_time(data.get("expiresAt")),
        error=acme_error(data.get("error")),
    )


def _authorization(data):
    return AcmeAuthorization(
        id=data["id"],
        account_id=data.get("accountID", ""),
        identifier=_identifier(data.get("identifier")),
        status=data.get("status", ""),
        wildcard=bool(data.get("wildcard")),
        challenge_ids=data.get("challengeIDs") or [],
        created_at=go_time(data.get("createdAt")),
        expires_at=go_time(data.get("expiresAt")),
        error=acme_error(data.get("error")),
    )


def _challenge(data):
    return AcmeChallenge(
        id=data["id"],
        account_id=data.get("accountID", ""),
        type=data.get("type", ""),
        status=data.get("status", ""),
        value=data.get("value", ""),
        validated_at=go_time(data.get("validatedAt")),
        created_at=go_time(data.get("createdAt")),
        error=acme_error(data.get("error")),
    )


def _acme_certificate(data):
    return AcmeCertificate(
        id=data["id"],
        account_id=data.get("accountID", ""),
        order_id=data.get("orderID", ""),
        created_at=go_time(data.get("createdAt")),
        # leaf is the PEM chain, base64-encoded as Go encodes []byte
        leaf=parse_cert(data["leaf"]) if data.get("leaf") else {},
    )


def _records(model, build, keys=None):
    records = []
    for key, data in _rows(model, keys):
        try:
            records.append(build(data))
        except (KeyError, TypeError) as e:
            log.warning("Cannot read %s %s: %s", model.__tablename__, key, e)
    return records


def acme_accounts():
    return _records(tables.AcmeAccount, _account)


def acme_account(account_id):
    data = _row(tables.AcmeAccount, account_id)
    return _account(data) if data else None


def acme_orders():
    return _records(tables.AcmeOrder, _order)


def acme_order(order_id):
    data = _row(tables.AcmeOrder, order_id)
    return _order(data) if data else None


def acme_authorizations(ids=None):
    return _records(tables.AcmeAuthz, _authorization, ids)


def acme_challenges(ids=None):
    return _records(tables.AcmeChallenge, _challenge, ids)


def acme_certificates(ids=None):
    return _records(tables.AcmeCert, _acme_certificate, ids)


def acme_certificate_id_by_serial(serial):
    """The ACME certificate that has this decimal serial, if it was issued over ACME."""
    data = _row(tables.AcmeSerialCert, serial)
    return data.get("certificateID") if data else None


def acme_certificate_count():
    return db.session.query(tables.AcmeCert).count()


# --- X.509 certificates -------------------------------------------------------------------------------


def _serial(nkey):
    """step-ca keys its x509 tables by the decimal serial number as ASCII bytes."""
    return bytes(nkey).decode("ascii", errors="backslashreplace")


def _provisioner_ref(metadata):
    provisioner = (metadata or {}).get("provisioner")
    if not provisioner:
        return None
    return ProvisionerRef(id=provisioner.get("id"), name=provisioner.get("name"), type=provisioner.get("type"))


def _x509_certificate(serial, der, metadata):
    try:
        cert = load_certificate(der)
        try:
            dns_names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            dns_names = []
        return Certificate(
            serial=serial,
            serial_hex=format(cert.serial_number, "x"),
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            key=key_description(cert),
            dns_names=dns_names,
            provisioner=_provisioner_ref(metadata),
        )
    except (ValueError, TypeError) as e:
        return Certificate(serial, "", "[error decoding cert]", "", None, None, "", [], _provisioner_ref(metadata), error=str(e))


def _certificate_metadata(serials=None):
    """x509_certs_data as {serial: metadata}, in one query (all rows, or only these serials)."""
    query = db.session.query(x509_tables.X509CertData)
    if serials is not None:
        query = query.filter(x509_tables.X509CertData.nkey.in_([s.encode("ascii") for s in serials]))
    metadata = {}
    for row in query.all():
        try:
            metadata[_serial(row.nkey)] = json.loads(bytes(row.nvalue))
        except ValueError as e:
            log.warning("Cannot parse x509_certs_data %s: %s", _serial(row.nkey), e)
    return metadata


def certificates(serials=None):
    """Every certificate (or those with these decimal serials), with the provisioner that issued it."""
    query = db.session.query(x509_tables.X509Cert)
    if serials is not None:
        serials = list(serials)
        if not serials:
            return []
        query = query.filter(x509_tables.X509Cert.nkey.in_([s.encode("ascii") for s in serials]))
    metadata = _certificate_metadata(serials)
    return [_x509_certificate(_serial(row.nkey), row.nvalue, metadata.get(_serial(row.nkey))) for row in query.all()]


def certificate(serial):
    found = certificates([serial])
    return found[0] if found else None


def certificate_der(serial):
    """The certificate as step-ca stored it (DER), or None."""
    row = db.session.get(x509_tables.X509Cert, serial.encode("ascii"))
    return bytes(row.nvalue) if row else None


def certificate_count():
    return db.session.query(x509_tables.X509Cert).count()


def certificate_serials():
    """The decimal serials of every certificate, from the table keys alone."""
    return {_serial(nkey) for (nkey,) in db.session.query(x509_tables.X509Cert.nkey)}


def _revocation(serial, data):
    return Revocation(
        serial=data.get("Serial") or serial,
        reason_code=data.get("ReasonCode"),
        reason=data.get("Reason") or "",
        revoked_at=go_time(data.get("RevokedAt")),
        provisioner_id=data.get("ProvisionerID") or None,
        mtls=bool(data.get("MTLS")),
        acme=bool(data.get("ACME")),
    )


def revocations(serials=None):
    """Every revocation, or those of these decimal serials."""
    query = db.session.query(x509_tables.RevokedX509Cert)
    if serials is not None:
        query = query.filter(x509_tables.RevokedX509Cert.nkey.in_([s.encode("ascii") for s in serials]))
    found = []
    for row in query.all():
        serial = _serial(row.nkey)
        try:
            found.append(_revocation(serial, json.loads(bytes(row.nvalue))))
        except ValueError as e:
            log.warning("Cannot parse revoked_x509_certs %s: %s", serial, e)
            found.append(Revocation(serial, None, "", None, None, False, False))
    return found


def revocation(serial):
    row = db.session.get(x509_tables.RevokedX509Cert, serial.encode("ascii"))
    if row is None:
        return None
    try:
        return _revocation(serial, json.loads(bytes(row.nvalue)))
    except ValueError:
        return Revocation(serial, None, "", None, None, False, False)


def revoked_serials():
    """The decimal serials step-ca has revoked, from the table keys alone."""
    return {_serial(nkey) for (nkey,) in db.session.query(x509_tables.RevokedX509Cert.nkey)}


def revocation_count():
    return db.session.query(x509_tables.RevokedX509Cert).count()


# --- Provisioners and admins --------------------------------------------------------------------------

# linkedca.Provisioner_Type, the number step-ca stores as a provisioner's "type"
PROVISIONER_TYPES = {1: "JWK", 2: "OIDC", 3: "GCP", 4: "AWS", 5: "AZURE", 6: "ACME", 7: "X5C", 8: "K8SSA", 9: "SSHPOP", 10: "SCEP", 11: "NEBULA"}
ADMIN_TYPES = {1: "ADMIN", 2: "SUPER_ADMIN"}


def _deleted(data):
    """step-ca soft-deletes: deletedAt is Go's zero time until then."""
    return go_time(data.get("deletedAt")) is not None


def provisioners(include_deleted=False):
    found = []
    for key, data in _rows(step_tables.StepProvisioner):
        try:
            record = Provisioner(
                id=data["id"],
                name=data["name"],
                type=PROVISIONER_TYPES.get(data.get("type"), str(data.get("type"))),
                deleted=_deleted(data),
                created_at=go_time(data.get("createdAt")),
            )
        except KeyError as e:
            log.warning("Cannot read provisioner %s: %s", key, e)
            continue
        if include_deleted or not record.deleted:
            found.append(record)
    return found


def admins(include_deleted=False):
    found = []
    for key, data in _rows(step_tables.StepAdmin):
        try:
            record = Admin(
                id=data["id"],
                subject=data.get("subject", ""),
                provisioner_id=data.get("provisionerID", ""),
                type=ADMIN_TYPES.get(data.get("type"), str(data.get("type"))),
                created_at=go_time(data.get("createdAt")),
                deleted=_deleted(data),
            )
        except KeyError as e:
            log.warning("Cannot read admin %s: %s", key, e)
            continue
        if include_deleted or not record.deleted:
            found.append(record)
    return found
