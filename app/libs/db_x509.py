# services/x509_service.py

import json
import re
from datetime import datetime

import pytz
from cryptography import x509

from app.extensions import db
from app.models.x509 import GeneratedCert, RevokedX509Cert, X509Cert, X509CertData

from .cert_utils import parse_cert_from_bytes
from .db_step import get_step_provisioners


def _serial(nkey):
    """step-ca keys its x509 tables by the decimal serial number as ASCII bytes."""
    return bytes(nkey).decode("ascii", errors="backslashreplace")


def _misdirected_serial(serial):
    """Before the revoke fix, the UI sent the hex of the ASCII serial (e.g. "3132" for "12"),
    so step-ca revoked a serial that was never issued. Return the serial that was meant."""
    if not re.fullmatch(r"(3[0-9])+", serial):
        return None
    return bytes.fromhex(serial).decode("ascii")


def _x509_metadata(serials=None):
    """x509_certs_data rows as {serial: data}, in a single query (all rows, or only `serials`)."""
    query = X509CertData.query
    if serials is not None:
        query = query.filter(X509CertData.nkey.in_([s.encode("ascii") for s in serials]))
    metadata = {}
    for row in query.all():
        try:
            metadata[_serial(row.nkey)] = json.loads(row.nvalue)
        except ValueError:
            pass
    return metadata


def _cert_entry(row, metadata):
    serial = _serial(row.nkey)
    try:
        parsed = parse_cert_from_bytes(row.nvalue)
        return {"nkey": serial, "data": parsed, "provisioner": metadata.get(serial, {}).get("provisioner") or {}}
    except Exception as e:
        return {"nkey": serial, "data": {"subject": "[error decoding cert]", "error": str(e)}, "provisioner": {}}


def _get_x509_certs_by_serials(serials):
    rows = X509Cert.query.filter(X509Cert.nkey.in_([s.encode("ascii") for s in serials])).all()
    metadata = _x509_metadata(serials)
    return [_cert_entry(row, metadata) for row in rows]


def get_x509_certs():
    metadata = _x509_metadata()
    return [_cert_entry(row, metadata) for row in X509Cert.query.all()]


def get_x509_certs_by_id(cert_id):
    if not (cert_id.isascii() and cert_id.isdigit()):
        return None
    certs = _get_x509_certs_by_serials([cert_id])
    return certs[0] if certs else None


def get_x509_certs_data():
    results = []
    for row in X509CertData.query.all():
        try:
            serial = _serial(row.nkey)
            value = json.loads(row.nvalue)
            results.append({"nkey": serial, "data": value})
        except Exception as e:
            results.append({"nkey": _serial(row.nkey), "data": {"error": str(e)}})
    return results


def get_revoked_x509_certs():
    certs = []
    for row in RevokedX509Cert.query.all():
        try:
            serial = _serial(row.nkey)
            value = json.loads(row.nvalue)
            certs.append({"nkey": serial, "data": value})
        except Exception as e:
            certs.append({"nkey": _serial(row.nkey), "data": {"error": str(e)}})
    return certs


def get_revoked_x509_with_cert_info():
    revocations = []
    rows = RevokedX509Cert.query.all()
    # Only load the certificates these revocations refer to
    keys = [_serial(row.nkey) for row in rows]
    wanted = set(keys) | {m for m in map(_misdirected_serial, keys) if m}
    cert_map = {c["nkey"]: c["data"] for c in _get_x509_certs_by_serials(wanted)} if wanted else {}
    prov_map = {p["data"]["id"]: p["data"]["name"] for p in get_step_provisioners() if "data" in p}

    for row in rows:
        try:
            key = _serial(row.nkey)
            value = json.loads(row.nvalue)
            cert_info = cert_map.get(key)
            if cert_info is None:
                intended = _misdirected_serial(key)
                if intended in cert_map:
                    value["misdirected_serial"] = intended
            value["provisioner_name"] = prov_map.get(value.get("ProvisionerID"), "—")
            revocations.append({"nkey": key, "data": value, "cert": cert_info})
        except Exception as e:
            revocations.append({"nkey": _serial(row.nkey), "data": {"error": str(e)}})
    return revocations


def get_x509_cert(serial):
    """Return the certificate with this decimal serial from step-ca's x509_certs, or None."""
    row = db.session.get(X509Cert, serial.encode("ascii"))
    return x509.load_der_x509_certificate(bytes(row.nvalue)) if row else None


def save_generated_cert(serial, common_name, provisioner, csr_pem):
    new_cert = GeneratedCert(serial=serial, common_name=common_name, provisioner=provisioner, csr=csr_pem)
    db.session.add(new_cert)
    db.session.commit()


def get_x509_active_certs(x509_certs=None):
    """Valid, non-revoked certificates. Pass the result of get_x509_certs() to avoid loading them twice."""
    if x509_certs is None:
        x509_certs = get_x509_certs()
    revoked_serials = {_serial(nkey) for (nkey,) in db.session.query(RevokedX509Cert.nkey)}
    now = datetime.utcnow().replace(tzinfo=pytz.UTC)
    active = []

    for cert in x509_certs:
        data = cert["data"]
        serial = cert["nkey"]

        if serial in revoked_serials:
            continue

        try:
            not_before = datetime.fromisoformat(data.get("not_before", "").replace("Z", "+00:00")).astimezone(pytz.UTC)
            not_after = datetime.fromisoformat(data.get("not_after", "").replace("Z", "+00:00")).astimezone(pytz.UTC)

            if not_before <= now <= not_after:
                active.append(cert)
        except Exception as e:
            print(f"Invalid cert dates for {serial}: {e}")

    return active
