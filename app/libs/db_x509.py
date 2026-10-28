# services/x509_service.py

import json
import re
from datetime import datetime
import pytz
from app.extensions import db
from .cert_utils import parse_cert_from_bytes
from .db_step import get_step_provisioners
from app.models.x509 import X509Cert, X509CertData, RevokedX509Cert, GeneratedCert


def _serial(nkey):
    """step-ca keys its x509 tables by the decimal serial number as ASCII bytes."""
    return bytes(nkey).decode("ascii", errors="backslashreplace")


def _misdirected_serial(serial):
    """Before the revoke fix, the UI sent the hex of the ASCII serial (e.g. "3132" for "12"),
    so step-ca revoked a serial that was never issued. Return the serial that was meant."""
    if not re.fullmatch(r"(3[0-9])+", serial):
        return None
    return bytes.fromhex(serial).decode("ascii")


def get_x509_certs():
    certs = []
    for row in X509Cert.query.all():
        try:
            cert_id = _serial(row.nkey)
            cert_bytes = row.nvalue
            parsed = parse_cert_from_bytes(cert_bytes)
            cert_metadata = get_x509_certs_data_by_id(cert_id)
            certs.append({"nkey": cert_id, "data": parsed, "provisioner": cert_metadata["data"]["provisioner"]})
        except Exception as e:
            certs.append({"nkey": _serial(row.nkey), "data": {"subject": "[error decoding cert]", "error": str(e)}})
    return certs


def get_x509_certs_by_id(cert_id):
    all_certs = get_x509_certs()
    return next((c for c in all_certs if c["nkey"] == cert_id), None)


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


def get_x509_certs_data_by_id(cert_id):
    for row in X509CertData.query.all():
        try:
            serial = _serial(row.nkey)
            value = json.loads(row.nvalue)
            if serial == cert_id:
                return {"nkey": serial, "data": value}
        except Exception as e:
            pass
    return None


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
    cert_map = {c["nkey"]: c["data"] for c in get_x509_certs()}
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


def get_generated_certs():
    return [
        {
            "id": row.id,
            "serial": row.serial,
            "common_name": row.common_name,
            "provisioner": row.provisioner,
            "created_at": row.created_at,
            "csr": row.csr,
            "certificate": row.certificate,
        }
        for row in GeneratedCert.query.order_by(GeneratedCert.created_at.desc()).all()
    ]


def get_generated_cert_by_serial(serial):
    row = GeneratedCert.query.filter_by(serial=serial).first()
    if row:
        return {
            "id": row.id,
            "serial": row.serial,
            "common_name": row.common_name,
            "provisioner": row.provisioner,
            "created_at": row.created_at,
            "csr": row.csr,
            "certificate": row.certificate,
        }
    return None


def save_generated_cert(serial, common_name, provisioner, csr_pem, cert_pem):
    new_cert = GeneratedCert(serial=serial, common_name=common_name, provisioner=provisioner, csr=csr_pem, certificate=cert_pem)
    db.session.add(new_cert)
    db.session.commit()


def get_x509_active_certs():
    x509_certs = get_x509_certs()
    revoked_certs = get_revoked_x509_certs()
    revoked_serials = {cert["nkey"] for cert in revoked_certs}
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

    # Enrich with `generated` flag
    generated_serials = {g["serial"] for g in get_generated_certs()}

    for cert in active:
        if cert["data"].get("serial") in generated_serials:
            cert["data"]["generated"] = True

    return active
