from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import base64
import re 




def format_pretty_date(dt):
    return dt.strftime("%B %d, %Y")

def parse_cert(leaf_b64):
    try:
        pem_bytes = base64.b64decode(leaf_b64)
        pem_str = pem_bytes.decode("utf-8", errors="ignore")

        match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem_str, re.DOTALL)
        if not match:
            return {"subject": "[invalid PEM format]"}

        cert_pem = f"-----BEGIN CERTIFICATE-----{match.group(1)}-----END CERTIFICATE-----"
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"), default_backend())

        # Extract SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = []

        # Extract Subject components
        subject = cert.subject
        get_attr = lambda oid: next((v.value for v in subject.get_attributes_for_oid(oid)), None)

        # Key Size
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            key_size = pubkey.key_size
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_size = pubkey.curve.name
        else:
            key_size = "Unknown"

        return {
            "subject": subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "not_before_pretty": format_pretty_date(cert.not_valid_before),
            "not_after_pretty": format_pretty_date(cert.not_valid_after),
            "serial": format(cert.serial_number, "x"),
            "organization": get_attr(NameOID.ORGANIZATION_NAME),
            "organizational_unit": get_attr(NameOID.ORGANIZATIONAL_UNIT_NAME),
            "locality": get_attr(NameOID.LOCALITY_NAME),
            "state": get_attr(NameOID.STATE_OR_PROVINCE_NAME),
            "country": get_attr(NameOID.COUNTRY_NAME),
            "key_size": key_size,
            "dns_names": san
        }

    except Exception as e:
        return {
            "subject": "[error decoding cert]",
            "error": str(e)
        }
    

def parse_cert_from_bytes(cert_bytes: bytes):
    try:

        def get_attr(name, oid):
            return next((v.value for v in name.get_attributes_for_oid(oid)), None)

        def format_date(dt):
            return dt.strftime("%B %d, %Y")

        try:
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        except ValueError:
            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())

        # Extract SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = []

        # Public key info
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            key_size = pubkey.key_size
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            key_size = pubkey.curve.name
        else:
            key_size = "Unknown"

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "organization": get_attr(cert.subject, NameOID.ORGANIZATION_NAME),
            "organizational_unit": get_attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "locality": get_attr(cert.subject, NameOID.LOCALITY_NAME),
            "state": get_attr(cert.subject, NameOID.STATE_OR_PROVINCE_NAME),
            "country": get_attr(cert.subject, NameOID.COUNTRY_NAME),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "not_before_pretty": format_date(cert.not_valid_before_utc),
            "not_after_pretty": format_date(cert.not_valid_after_utc),
            "serial": format(cert.serial_number, "x"),
            "key_size": key_size,
            "dns_names": san
        }

    except Exception as e:
        return {"subject": "[error decoding cert]", "error": str(e)}


def decode_certificate(cert_pem_raw):
    # Load the certificate
    cert_pem = cert_pem_raw.replace('\\n', '\n')
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
    
    # Extract basic information
    subject = cert.subject
    issuer = cert.issuer
    serial_number = cert.serial_number
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    # Extract Common Name
    common_name = None
    for attribute in subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            common_name = attribute.value
            break

    # Extract SANs (Subject Alternative Names) if present
    try:
        san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    return {
        "common_name": common_name,
        "subject": subject.rfc4514_string(),
        "issuer": issuer.rfc4514_string(),
        "serial_number": str(serial_number),
        "valid_from": not_before,
        "valid_to": not_after,
        "sans": sans,
    }


def get_subject_string(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())
    subject = csr.subject
    return subject.rfc4514_string()

def extract_sans_from_csr(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
        return sans
    except x509.ExtensionNotFound:
        return None