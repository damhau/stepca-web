"""SSH certificates as step-ca stores them: the OpenSSH wire format (RFC 4253 strings, PROTOCOL.certkeys), which is
what the base64 part of an `id_ed25519-cert.pub` file holds. Parsing is left to `cryptography`; this module turns
what it returns into plain values, and reads the key type that precedes them."""

import base64
import hashlib
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, ssh

# OpenSSH writes "no expiry" as 2**64-1 and "valid from the beginning" as 0; the largest date Python has is in 9999
_MAX_TIMESTAMP = 253_402_300_799

_NIST_CURVES = {"secp256r1": "nistp256", "secp384r1": "nistp384", "secp521r1": "nistp521"}


@dataclass(frozen=True)
class SshCertInfo:
    kind: str  # "user" or "host"
    key_id: str
    principals: list[str]
    valid_after: datetime | None  # None: valid from the beginning
    valid_before: datetime | None  # None: never expires
    key_type: str  # "ED25519", "RSA 3072", "ECDSA nistp256"
    fingerprint: str  # of the certified key, as `ssh-keygen -l` prints it
    ca_key_type: str
    ca_fingerprint: str  # of the key that signed it
    critical_options: dict[str, str]
    extensions: dict[str, str]


def _timestamp(value: int, *, none_at_zero: bool) -> datetime | None:
    if (none_at_zero and value == 0) or value > _MAX_TIMESTAMP:
        return None
    return datetime.fromtimestamp(value, UTC)


def key_description(key) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {_NIST_CURVES.get(key.curve.name, key.curve.name)}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ED25519"
    return type(key).__name__


def fingerprint(key) -> str:
    """SHA256:... of a public key, the way OpenSSH prints it (base64 without padding)."""
    blob = base64.b64decode(key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def key_type_name(blob: bytes) -> str:
    """The certificate's key type, such as "ssh-ed25519-cert-v01@openssh.com": the blob's first string."""
    if len(blob) < 4:
        raise ValueError("Not an SSH certificate: too short")
    (length,) = struct.unpack(">I", blob[:4])
    name = blob[4 : 4 + length]
    if length == 0 or len(name) != length or not name.isascii():
        raise ValueError("Not an SSH certificate: no key type")
    return name.decode("ascii")


def public_line(blob: bytes) -> str:
    """The certificate as an `*-cert.pub` file has it, without the comment: key type, then the blob in base64."""
    return f"{key_type_name(blob)} {base64.b64encode(blob).decode()}"


def _text(value: bytes) -> str:
    return value.decode(errors="replace")


@lru_cache(maxsize=20_000)
def parse(blob: bytes) -> SshCertInfo:
    """What the wire-format certificate says. ValueError for anything that isn't a certificate this can read
    (cryptography reads RSA, ECDSA and Ed25519 ones). Cached by content, so listing thousands of certificates
    again and again parses each of them once."""
    line = public_line(blob).encode()
    try:
        cert = ssh.load_ssh_public_identity(line)
    except UnsupportedAlgorithm as e:
        raise ValueError(f"Unsupported SSH key type ({key_type_name(blob)})") from e
    if not isinstance(cert, ssh.SSHCertificate):
        raise ValueError("Not an SSH certificate: a plain public key")
    ca_key = cert.signature_key()
    return SshCertInfo(
        kind="host" if cert.type == ssh.SSHCertificateType.HOST else "user",
        key_id=_text(cert.key_id),
        principals=[_text(principal) for principal in cert.valid_principals],
        valid_after=_timestamp(cert.valid_after, none_at_zero=True),
        valid_before=_timestamp(cert.valid_before, none_at_zero=False),
        key_type=key_description(cert.public_key()),
        fingerprint=fingerprint(cert.public_key()),
        ca_key_type=key_description(ca_key),
        ca_fingerprint=fingerprint(ca_key),
        critical_options={_text(name): _text(value) for name, value in cert.critical_options.items()},
        extensions={_text(name): _text(value) for name, value in cert.extensions.items()},
    )
