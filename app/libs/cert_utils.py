import base64
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID, ObjectIdentifier

PEM_CERTIFICATE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)

# step-ca's certificate extension naming the provisioner that issued a certificate
STEP_PROVISIONER_OID = ObjectIdentifier("1.3.6.1.4.1.37476.9000.64.1")


def _der_element(data, pos):
    """One DER element at `pos`: (contents, position after it)."""
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[pos : pos + size], "big")
        pos += size
    return data[pos : pos + length], pos + length


def issuing_provisioner(cert):
    """Name of the step-ca provisioner that issued `cert`, or None.

    The extension is SEQUENCE { type INTEGER, name OCTET STRING, credentialID, keyValuePairs }.
    """
    try:
        raw = cert.extensions.get_extension_for_oid(STEP_PROVISIONER_OID).value.value
    except x509.ExtensionNotFound:
        return None
    sequence, _ = _der_element(raw, 0)
    _, pos = _der_element(sequence, 0)
    name, _ = _der_element(sequence, pos)
    return name.decode()


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


def fingerprint(cert):
    """SHA-256 fingerprint in hex, as `step certificate fingerprint` prints it."""
    return cert.fingerprint(hashes.SHA256()).hex()


KEY_USAGES = [
    ("digital_signature", "Digital signature"),
    ("content_commitment", "Content commitment"),
    ("key_encipherment", "Key encipherment"),
    ("data_encipherment", "Data encipherment"),
    ("key_agreement", "Key agreement"),
    ("key_cert_sign", "Certificate sign"),
    ("crl_sign", "CRL sign"),
]
EXTENDED_KEY_USAGES = {
    ExtendedKeyUsageOID.SERVER_AUTH: "TLS server",
    ExtendedKeyUsageOID.CLIENT_AUTH: "TLS client",
    ExtendedKeyUsageOID.CODE_SIGNING: "Code signing",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "Email protection",
    ExtendedKeyUsageOID.TIME_STAMPING: "Time stamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP signing",
}


def general_name(name):
    if isinstance(name, x509.DNSName):
        return f"DNS:{name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP:{name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"email:{name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI:{name.value}"
    return str(name.value)


def describe_extension(extension):
    value = extension.value
    if isinstance(value, x509.SubjectAlternativeName):
        return ", ".join(general_name(name) for name in value)
    if isinstance(value, x509.KeyUsage):
        return ", ".join(label for attribute, label in KEY_USAGES if getattr(value, attribute))
    if isinstance(value, x509.ExtendedKeyUsage):
        return ", ".join(EXTENDED_KEY_USAGES.get(oid, oid.dotted_string) for oid in value)
    if isinstance(value, x509.BasicConstraints):
        return f"CA: {'yes' if value.ca else 'no'}" + (f", path length {value.path_length}" if value.path_length is not None else "")
    if isinstance(value, x509.SubjectKeyIdentifier):
        return value.digest.hex()
    if isinstance(value, x509.AuthorityKeyIdentifier):
        return value.key_identifier.hex() if value.key_identifier else "—"
    if isinstance(value, x509.CRLDistributionPoints):
        return ", ".join(general_name(name) for point in value for name in point.full_name or [])
    if isinstance(value, x509.AuthorityInformationAccess):
        return ", ".join(general_name(description.access_location) for description in value)
    return None


EXTENSION_NAMES = {
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "Subject alternative names",
    ExtensionOID.KEY_USAGE: "Key usage",
    ExtensionOID.EXTENDED_KEY_USAGE: "Extended key usage",
    ExtensionOID.BASIC_CONSTRAINTS: "Basic constraints",
    ExtensionOID.SUBJECT_KEY_IDENTIFIER: "Subject key identifier",
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "Authority key identifier",
    ExtensionOID.CRL_DISTRIBUTION_POINTS: "CRL distribution points",
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "Authority information access",
    STEP_PROVISIONER_OID: "step-ca provisioner",
}


def certificate_extensions(cert):
    """[(name, value, critical)] for each extension; unknown ones show their OID."""
    rows = []
    for extension in cert.extensions:
        if extension.oid == STEP_PROVISIONER_OID:
            value = issuing_provisioner(cert)
        else:
            value = describe_extension(extension)
        name = EXTENSION_NAMES.get(extension.oid, extension.oid.dotted_string)
        rows.append((name, value if value is not None else "(not decoded)", extension.critical))
    return rows


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


def csr_sans(csr):
    """Every subject alternative name of a CSR, as step-ca compares them with a token's "sans"."""
    try:
        names = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return (
        names.get_values_for_type(x509.DNSName)
        + [str(ip) for ip in names.get_values_for_type(x509.IPAddress)]
        + names.get_values_for_type(x509.RFC822Name)
        + names.get_values_for_type(x509.UniformResourceIdentifier)
    )


def describe_csr(csr_pem):
    """What a CSR asks for, for the sign form's preview. Raises ValueError if it isn't a PEM CSR."""
    csr = x509.load_pem_x509_csr(csr_pem.strip().encode())
    common_names = [a.value for a in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    key = csr.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_name = f"RSA {key.key_size} bit"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_name = f"EC {key.curve.name}"
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_name = "Ed25519"
    else:
        key_name = "Unknown"
    return {
        "subject": csr.subject.rfc4514_string(),
        "common_name": common_names[0] if common_names else None,
        "sans": csr_sans(csr),
        "key": key_name,
        "signature_valid": csr.is_signature_valid,
    }
