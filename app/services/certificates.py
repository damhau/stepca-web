"""X.509 certificates: a certificate's page and downloads, signing, revoking, and revocations that missed."""

import re
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from app.extensions import db
from app.libs.audit import audit
from app.libs.cert_utils import certificate_extensions, load_certificate
from app.libs.provisioners import duration_seconds
from app.models.x509 import GeneratedCert
from app.services import acme, ca, inventory, provisioners
from app.stepca import store
from app.stepca.client import SignError
from app.stepca.records import Certificate, Revocation

# Every RFC 5280 reason code, to name the ones step-ca recorded
REASON_NAMES = {
    0: "Unspecified",
    1: "Key compromise",
    2: "CA compromise",
    3: "Affiliation changed",
    4: "Superseded",
    5: "Cessation of operation",
    6: "Certificate hold",
    8: "Remove from CRL",
    9: "Privilege withdrawn",
    10: "AA compromise",
}

# The reasons that make sense for a passive revocation, offered by the revoke dialog
REVOCATION_REASONS = [(code, REASON_NAMES[code]) for code in (0, 1, 3, 4, 5, 9)]


def is_serial(text):
    """Certificates are identified by their decimal serial, as step-ca stores them."""
    return text.isascii() and text.isdigit()


def exists(serial):
    return is_serial(serial) and store.certificate_der(serial) is not None


def misdirected_serial(serial):
    """Before the revoke fix, the UI sent the hex of the ASCII serial (e.g. "3132" for "12"), so step-ca
    revoked a serial that was never issued. The serial that was meant, or None."""
    if not re.fullmatch(r"(3[0-9])+", serial):
        return None
    return bytes.fromhex(serial).decode("ascii")


@dataclass(frozen=True)
class RevokedRow:
    revocation: Revocation
    certificate: Certificate | None
    # Set for a revocation by an older version of the UI: the certificate that is still valid
    misdirected_serial: str | None
    provisioner_name: str | None


def revoked():
    revocations = store.revocations()
    # Only read the certificates these revocations refer to
    wanted = {r.serial for r in revocations} | {m for r in revocations if (m := misdirected_serial(r.serial))}
    certificates = {cert.serial: cert for cert in store.certificates(wanted)}
    names = provisioners.names_by_id(include_deleted=True)
    rows = []
    for revocation in revocations:
        certificate = certificates.get(revocation.serial)
        intended = misdirected_serial(revocation.serial) if certificate is None else None
        rows.append(RevokedRow(revocation, certificate, intended if intended in certificates else None, names.get(revocation.provisioner_id)))
    return rows


FORMATS = ("pem", "der", "chain")


def download(serial, file_format, intermediates):
    """(content, filename, content type) of a certificate, or None if there is no such certificate.
    `intermediates`: returns the CA's intermediates, for the chain (it may raise the CA's errors)."""
    der = store.certificate_der(serial) if is_serial(serial) else None
    if der is None:
        return None
    cert = load_certificate(der)
    common_names = [a.value for a in cert.subject if a.oid.dotted_string == "2.5.4.3"]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", common_names[0] if common_names else serial)
    if file_format == "der":
        return cert.public_bytes(serialization.Encoding.DER), f"{name}.crt", "application/pkix-cert"
    if file_format == "chain":
        found = intermediates()
        # The intermediate that issued it; step-ca usually has one
        issuers = [i for i in found if i.subject == cert.issuer] or found
        content = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [cert, *issuers])
        return content, f"{name}-chain.pem", "application/x-pem-file"
    return cert.public_bytes(serialization.Encoding.PEM), f"{name}.pem", "application/x-pem-file"


def record_signed(serial, common_name, provisioner_name, csr_pem):
    """Keep the CSR of a certificate signed from the UI, in the app's own database."""
    db.session.add(GeneratedCert(serial=serial, common_name=common_name, provisioner=provisioner_name, csr=csr_pem))
    db.session.commit()


def sign(csr_pem, provisioner_name, password, valid_for=None):
    """Sign a CSR with a JWK provisioner, keep its CSR and audit it. The decimal serial, or SignError."""
    try:
        if valid_for:
            try:
                duration_seconds(valid_for)
            except ValueError as e:
                raise SignError(f"Validity: {e}") from e
        certificate = ca.client().sign(csr_pem, provisioner_name, password, not_after=valid_for or None)
    except SignError as e:
        audit("sign", "", success=False, detail=f"provisioner={provisioner_name}: {e}")
        raise
    serial = str(certificate.serial_number)  # decimal, like step-ca's x509_certs key
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = str(common_names[0].value) if common_names else None
    record_signed(serial, common_name, provisioner_name, csr_pem)
    audit("sign", serial, detail=f"cn={common_name} provisioner={provisioner_name}")
    inventory.refresh(force=True)
    return serial


def revoke(serial, reason_code):
    """Revoke a certificate step-ca issued, passively (step-ca stops vouching for it), and audit it.
    ValueError for an unknown certificate or reason; the CA's errors otherwise."""
    reasons = dict(REVOCATION_REASONS)
    if reason_code not in reasons:
        raise ValueError("Invalid revocation reason")
    if not exists(serial):
        raise LookupError(f"Certificate {serial} not found")
    try:
        ca.client().revoke(serial, reason_code=reason_code, reason=reasons[reason_code])
    except (RuntimeError, *ca.CA_ERRORS) as e:
        audit("revoke", serial, success=False, detail=str(e))
        raise
    audit("revoke", serial, detail=reasons[reason_code])
    inventory.refresh(force=True)


@dataclass(frozen=True)
class Detail:
    """A certificate's page: the inventory's view of it, and what only the certificate itself has."""

    certificate: inventory.InventoryItem
    extensions: list[dict]
    revocation: dict | None
    acme_order_id: str | None
    pem: str


def detail(serial):
    """Everything about a certificate, or None if step-ca has no such certificate."""
    if not is_serial(serial):
        return None
    item = inventory.certificate(serial)
    if item is None and store.certificate_der(serial) is not None:
        # Issued since the last check
        inventory.refresh(force=True)
        item = inventory.certificate(serial)
    der = store.certificate_der(serial)
    if item is None or der is None:
        return None
    cert = load_certificate(der)
    revocation = store.revocation(serial)
    names = provisioners.names_by_id(include_deleted=True) if revocation else {}
    return Detail(
        certificate=item,
        extensions=[{"name": name, "value": value, "critical": critical} for name, value, critical in certificate_extensions(cert)],
        revocation={**asdict(revocation), "provisioner_name": names.get(revocation.provisioner_id)} if revocation else None,
        acme_order_id=acme.order_id_for_serial(serial),
        pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
    )


def unmatched_revocations():
    """Revocations of serials step-ca never issued, with the certificate an older UI meant to revoke."""
    names = provisioners.names_by_id(include_deleted=True)
    return [
        {"revocation": {**asdict(row.revocation), "provisioner_name": names.get(row.revocation.provisioner_id)}, "misdirected_serial": row.misdirected_serial}
        for row in revoked()
        if row.certificate is None
    ]
