import base64
import re

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

PEM_CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def load_certificate(data):
    """The first certificate in PEM bytes, or the certificate in DER bytes."""
    data = bytes(data)
    match = PEM_CERTIFICATE.search(data)
    if match:
        return x509.load_pem_x509_certificate(match.group(0))
    return x509.load_der_x509_certificate(data)


def key_description(cert):
    """RSA key size in bits (an int), or the curve name."""
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key.curve.name
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return "Unknown"


def describe_certificate(cert):
    """The fields the certificate lists and pages show."""
    try:
        dns_names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns_names = []
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": format(cert.serial_number, "x"),
        "serial_dec": str(cert.serial_number),
        "key_size": key_description(cert),
        "dns_names": dns_names,
    }


def parse_cert_from_bytes(cert_bytes):
    """describe_certificate() of PEM or DER bytes, or an error entry for a row that doesn't parse."""
    try:
        return describe_certificate(load_certificate(cert_bytes))
    except (ValueError, TypeError) as e:
        return {"subject": "[error decoding cert]", "error": str(e)}


def parse_cert(leaf_b64):
    """An ACME certificate's "leaf": the base64 of its PEM chain."""
    try:
        return parse_cert_from_bytes(base64.b64decode(leaf_b64))
    except (ValueError, TypeError) as e:
        return {"subject": "[error decoding cert]", "error": str(e)}


def extract_sans_from_csr(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
        return sans
    except x509.ExtensionNotFound:
        return None
