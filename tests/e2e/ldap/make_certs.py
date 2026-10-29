"""A test CA, a TLS certificate (names: openldap, localhost) and DH parameters for the OpenLDAP container."""

import base64
import datetime
import sys
import textwrap
from decimal import Decimal, getcontext
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def der_integer(value):
    body = value.to_bytes(value.bit_length() // 8 + 1, "big")  # a leading zero byte keeps it positive
    return b"\x02" + der_length(len(body)) + body


def der_length(length):
    if length < 0x80:
        return bytes([length])
    size = (length.bit_length() + 7) // 8
    return bytes([0x80 | size]) + length.to_bytes(size, "big")


def ffdhe2048_pem():
    """The RFC 7919 ffdhe2048 group in PKCS#3 PEM (what OpenLDAP with GnuTLS reads), from its definition:
    p = 2^2048 - 2^1984 + (floor(2^1918 * e) + 560316) * 2^64 - 1, g = 2.

    Without DH parameters the image generates its own at first start, which takes up to minutes.
    """
    getcontext().prec = 1200
    e, term, k = Decimal(1), Decimal(1), 1
    while term > Decimal(10) ** -1150:
        term /= k
        e += term
        k += 1
    p = 2**2048 - 2**1984 + (int(Decimal(2**1918) * e) + 560316) * 2**64 - 1
    body = der_integer(p) + der_integer(2)
    der = b"\x30" + der_length(len(body)) + body
    lines = textwrap.wrap(base64.b64encode(der).decode(), 64)
    return ("-----BEGIN DH PARAMETERS-----\n" + "\n".join(lines) + "\n-----END DH PARAMETERS-----\n").encode()


def main(out):
    out.mkdir(parents=True, exist_ok=True)
    # Valid from an hour ago, so a small clock difference doesn't make them "not yet valid"
    now = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name("E2E LDAP CA"))
        .issuer_name(name("E2E LDAP CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name("openldap"))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("openldap"), x509.DNSName("localhost")]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (out / "dhparam.pem").write_bytes(ffdhe2048_pem())
    (out / "ca.crt").write_bytes(pem(ca))
    (out / "ldap.crt").write_bytes(pem(cert))
    (out / "ldap.key").write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
