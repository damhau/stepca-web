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
