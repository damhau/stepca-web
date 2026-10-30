"""Typed records for what step-ca stores, independent of its storage format."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class AcmeIdentifier:
    type: str
    value: str


@dataclass(frozen=True)
class AcmeAccount:
    id: str
    status: str
    contact: list[str]
    provisioner_id: str | None
    provisioner_name: str | None
    created_at: datetime | None
    deactivated_at: datetime | None


@dataclass(frozen=True)
class AcmeOrder:
    id: str
    account_id: str
    provisioner_id: str | None
    identifiers: list[AcmeIdentifier]
    authorization_ids: list[str]
    status: str
    certificate_id: str | None
    not_before: datetime | None
    not_after: datetime | None
    created_at: datetime | None
    expires_at: datetime | None
    error: str | None


@dataclass(frozen=True)
class AcmeAuthorization:
    id: str
    account_id: str
    identifier: AcmeIdentifier
    status: str
    wildcard: bool
    challenge_ids: list[str]
    created_at: datetime | None
    expires_at: datetime | None
    error: str | None


@dataclass(frozen=True)
class AcmeChallenge:
    id: str
    account_id: str
    type: str
    status: str
    value: str
    validated_at: datetime | None
    created_at: datetime | None
    error: str | None


@dataclass(frozen=True)
class AcmeCertificate:
    id: str
    account_id: str
    order_id: str
    created_at: datetime | None
    # The leaf, as the certificate lists show it (cert_utils.describe_certificate), or an error entry
    leaf: dict = field(default_factory=dict)

    @property
    def serial(self) -> str | None:
        return self.leaf.get("serial_dec")


@dataclass(frozen=True)
class ProvisionerRef:
    """The provisioner step-ca recorded for a certificate (x509_certs_data)."""

    id: str | None
    name: str | None
    type: str | None


@dataclass(frozen=True)
class Certificate:
    serial: str  # decimal, the key step-ca stores it under
    serial_hex: str
    subject: str
    issuer: str
    not_before: datetime | None
    not_after: datetime | None
    key: int | str  # RSA size in bits, or the curve
    dns_names: list[str]
    provisioner: ProvisionerRef | None
    # Set when the stored certificate doesn't parse; the other fields are then empty
    error: str | None = None

    def is_valid_at(self, when: datetime) -> bool:
        return bool(self.not_before and self.not_after and self.not_before <= when <= self.not_after)

    def days_left(self, when: datetime) -> int | None:
        return (self.not_after - when).days if self.not_after else None


@dataclass(frozen=True)
class Revocation:
    serial: str  # decimal, as step-ca stores it
    reason_code: int | None
    reason: str
    revoked_at: datetime | None
    provisioner_id: str | None
    mtls: bool
    acme: bool


@dataclass(frozen=True)
class Provisioner:
    """A provisioner as step-ca's database stores it (the Admin API is the authority for its settings)."""

    id: str
    name: str
    type: str  # "JWK", "ACME", ...
    deleted: bool
    created_at: datetime | None = None


@dataclass(frozen=True)
class Admin:
    id: str
    subject: str
    provisioner_id: str
    type: str  # "ADMIN" or "SUPER_ADMIN"
    created_at: datetime | None
    deleted: bool
