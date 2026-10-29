"""X.509 certificates: what counts as active or expiring, revocations, a certificate's page and its downloads."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization

from app.extensions import db
from app.libs.cert_utils import certificate_extensions, load_certificate
from app.models.x509 import GeneratedCert
from app.services import acme, provisioners
from app.stepca import store
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


def now():
    return datetime.now(UTC)


def is_serial(text):
    """Certificates are identified by their decimal serial, as step-ca stores them."""
    return text.isascii() and text.isdigit()


def exists(serial):
    return is_serial(serial) and store.certificate_der(serial) is not None


def all_certificates():
    return store.certificates()


def active(certificates=None, when=None):
    """Valid now and not revoked. Pass all_certificates() to avoid reading them twice."""
    when = when or now()
    certificates = store.certificates() if certificates is None else certificates
    revoked = store.revoked_serials()
    return [cert for cert in certificates if cert.serial not in revoked and cert.is_valid_at(when)]


@dataclass(frozen=True)
class Expiring:
    certificate: Certificate
    days_left: int


def expiring(days, certificates=None, when=None):
    """Active certificates that expire within `days`, soonest first."""
    when = when or now()
    found = [Expiring(cert, cert.days_left(when)) for cert in active(certificates, when) if cert.days_left(when) < days]
    return sorted(found, key=lambda item: item.certificate.not_after)


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


@dataclass(frozen=True)
class CertificateView:
    certificate: Certificate
    status: str  # valid, expired, not yet valid or revoked
    days_left: int | None
    revocation: Revocation | None
    extensions: list
    acme_order_id: str | None


def view(serial):
    """Everything the certificate page shows, or None if there is no such certificate."""
    if not is_serial(serial):
        return None
    certificate = store.certificate(serial)
    if certificate is None or certificate.error:
        return None
    when = now()
    revocation = store.revocation(serial)
    if revocation:
        status = "revoked"
    elif certificate.not_after < when:
        status = "expired"
    elif certificate.not_before > when:
        status = "not yet valid"
    else:
        status = "valid"
    return CertificateView(
        certificate=certificate,
        status=status,
        days_left=certificate.days_left(when),
        revocation=revocation,
        extensions=certificate_extensions(load_certificate(store.certificate_der(serial))),
        acme_order_id=acme.order_id_for_serial(serial),
    )


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
