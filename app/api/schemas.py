"""What the JSON API takes and returns. These models are also its OpenAPI document, from which the frontend's
TypeScript types are generated (frontend/openapi.json): a change here is a compile error there."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.libs.provisioners import duration_seconds
from app.services.inventory import SortKey, Status, StatusFilter

Role = Literal["viewer", "operator", "admin"]


class Model(BaseModel):
    """Responses are built from the services' dataclasses."""

    model_config = ConfigDict(from_attributes=True)


class Error(BaseModel):
    error: str


class ValidationProblem(BaseModel):
    """One problem with the request, as pydantic reports it (without the submitted value)."""

    type: str
    loc: list[str | int]
    msg: str


# --- Lists ----------------------------------------------------------------------------------------------


class ListQuery(BaseModel):
    page: int = Field(1, ge=1)
    per_page: int = Field(50, ge=1, le=500)
    q: str = Field("", max_length=200, description="Text the rows must contain")
    # csv: every matching row (not only this page), as a file
    format: Literal["json", "csv"] = "json"


class PageInfo(Model):
    total: int
    page: int
    per_page: int


# --- Session --------------------------------------------------------------------------------------------


class SessionInfo(Model):
    authenticated: bool
    user: str | None
    role: Role | None
    # Sent back in the X-CSRFToken header of every POST, PUT, PATCH and DELETE
    csrf_token: str
    service_control: bool


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)


# --- Certificates ---------------------------------------------------------------------------------------


class CertificateItem(Model):
    serial: str = Field(description="Decimal, as step-ca stores it")
    serial_hex: str
    subject: str
    common_name: str | None
    issuer: str
    not_before: datetime | None
    not_after: datetime | None
    key: str
    dns_names: list[str]
    provisioner_id: str | None
    provisioner_name: str | None
    provisioner_type: str | None
    error: str | None
    status: Status
    days_left: int | None
    revoked_at: datetime | None
    revocation_reason: str | None
    revocation_reason_code: int | None


class CertificateListQuery(ListQuery):
    status: StatusFilter = "all"
    days: int = Field(30, ge=1, le=3650, description="With status=expiring: expires within this many days")
    provisioner: str | None = Field(None, max_length=200)
    sort: SortKey = "not_before"
    order: Literal["asc", "desc"] = "desc"


class CertificatePage(PageInfo):
    items: list[CertificateItem]
    # Certificates step-ca has that are still being indexed
    pending: int


class Extension(Model):
    name: str
    value: str
    critical: bool


class RevocationInfo(Model):
    serial: str
    reason_code: int | None
    reason: str
    revoked_at: datetime | None
    provisioner_id: str | None
    provisioner_name: str | None
    mtls: bool
    acme: bool


class CertificateDetail(Model):
    certificate: CertificateItem
    extensions: list[Extension]
    revocation: RevocationInfo | None
    acme_order_id: str | None
    pem: str


class SerialPath(BaseModel):
    serial: str = Field(pattern=r"^[0-9]{1,80}$")


class DownloadQuery(BaseModel):
    format: Literal["pem", "der", "chain"] = "pem"


class RevokeBody(BaseModel):
    reason_code: int


class SignBody(BaseModel):
    csr_pem: str = Field(min_length=1, max_length=64 * 1024)
    provisioner: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=1024)
    valid_for: str | None = Field(None, max_length=40, description="A Go duration such as 24h, within the provisioner's limits")

    @field_validator("valid_for")
    @classmethod
    def go_duration(cls, value):
        if value:
            duration_seconds(value.strip())
            return value.strip()
        return None


class SignResult(Model):
    serial: str


class CsrBody(BaseModel):
    csr_pem: str = Field(min_length=1, max_length=64 * 1024)


class CsrDescription(Model):
    subject: str
    common_name: str | None
    sans: list[str]
    key: str
    signature_valid: bool


class UnmatchedRevocation(Model):
    revocation: RevocationInfo
    # Revoked by an older version of the UI with a wrong serial: the certificate that was meant, still valid
    misdirected_serial: str | None


class UnmatchedRevocationList(Model):
    items: list[UnmatchedRevocation]


class NameList(Model):
    names: list[str]


class NameCount(Model):
    name: str
    count: int


class Dashboard(Model):
    total: int
    valid: int
    expiring: int
    expired: int
    revoked: int
    acme_certificates: int
    provisioners: int
    issued_by_provisioner: list[NameCount]
    acme_orders_by_status: list[NameCount]
    expiring_soon: list[CertificateItem]
    pending: int


class Option(Model):
    value: str
    label: str


class RevocationReason(Model):
    code: int
    name: str


class Reference(Model):
    """The fixed choices the forms offer."""

    revocation_reasons: list[RevocationReason]
    acme_challenges: list[Option]
    signing_provisioners: list[str]


# --- ACME -----------------------------------------------------------------------------------------------


class AcmeIdentifier(Model):
    type: str
    value: str


class AcmeAccountItem(Model):
    id: str
    status: str
    contact: list[str]
    provisioner_id: str | None
    provisioner_name: str | None
    created_at: datetime | None
    deactivated_at: datetime | None


class AcmeOrderItem(Model):
    id: str
    account_id: str
    provisioner_id: str | None
    identifiers: list[AcmeIdentifier]
    authorization_ids: list[str]
    status: str
    certificate_id: str | None
    certificate_serial: str | None
    not_before: datetime | None
    not_after: datetime | None
    created_at: datetime | None
    expires_at: datetime | None
    error: str | None


class AcmeAuthorizationItem(Model):
    id: str
    account_id: str
    identifier: AcmeIdentifier
    status: str
    wildcard: bool
    challenge_ids: list[str]
    created_at: datetime | None
    expires_at: datetime | None
    error: str | None
    order_id: str | None


class AcmeChallengeItem(Model):
    id: str
    account_id: str
    type: str
    status: str
    value: str
    validated_at: datetime | None
    created_at: datetime | None
    error: str | None
    order_id: str | None


class AcmeCertificateItem(Model):
    id: str
    account_id: str
    order_id: str
    created_at: datetime | None
    serial: str | None
    subject: str | None
    dns_names: list[str]
    not_before: datetime | None
    not_after: datetime | None
    error: str | None


class AcmeListQuery(ListQuery):
    status: str | None = Field(None, max_length=40)


class AcmeAccountPage(PageInfo):
    items: list[AcmeAccountItem]


class AcmeOrderPage(PageInfo):
    items: list[AcmeOrderItem]


class AcmeAuthorizationPage(PageInfo):
    items: list[AcmeAuthorizationItem]


class AcmeChallengePage(PageInfo):
    items: list[AcmeChallengeItem]


class AcmeCertificatePage(PageInfo):
    items: list[AcmeCertificateItem]


class AcmeAccountDetail(Model):
    account: AcmeAccountItem
    orders: list[AcmeOrderItem]


class AcmeAuthorizationView(Model):
    authorization: AcmeAuthorizationItem
    challenges: list[AcmeChallengeItem]


class AcmeOrderDetail(Model):
    order: AcmeOrderItem
    account: AcmeAccountItem | None
    authorizations: list[AcmeAuthorizationView]
    certificate: AcmeCertificateItem | None


class IdPath(BaseModel):
    id: str = Field(min_length=1, max_length=200)


# --- Provisioners and admins ----------------------------------------------------------------------------

AcmeChallengeName = Literal["HTTP_01", "DNS_01", "TLS_ALPN_01"]


class Durations(Model):
    """Go durations such as 24h, 90m or 1h30m; None: the CA's default."""

    default: str | None = None
    min: str | None = None
    max: str | None = None

    @field_validator("default", "min", "max")
    @classmethod
    def go_duration(cls, value):
        if value is None or not value.strip():
            return None
        duration_seconds(value.strip())
        return value.strip()


class AcmeOptions(Model):
    challenges: list[AcmeChallengeName] = Field(default_factory=list, description="None: step-ca allows http-01, dns-01 and tls-alpn-01")
    require_eab: bool = False
    force_cn: bool = False


class ProvisionerItem(Model):
    name: str
    type: str
    id: str | None
    x509_enabled: bool
    durations: Durations
    disable_renewal: bool
    allow_renewal_after_expiry: bool
    acme: AcmeOptions | None
    created_at: datetime | None
    # The app's own provisioner: it must keep issuing the app's 24-hour admin certificate
    is_app_provisioner: bool
    # The provisioner as step-ca's Admin API returns it
    raw: dict[str, Any]


class ProvisionerList(Model):
    provisioners: list[ProvisionerItem]


class ProvisionerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: Literal["JWK", "ACME"]
    password: str | None = Field(None, max_length=1024, description="JWK: encrypts the provisioner's key")
    durations: Durations = Field(default_factory=Durations)
    acme: AcmeOptions | None = None


class ProvisionerUpdate(BaseModel):
    x509_enabled: bool
    durations: Durations = Field(default_factory=Durations)
    disable_renewal: bool = False
    allow_renewal_after_expiry: bool = False
    acme: AcmeOptions | None = None


class NamePath(BaseModel):
    name: str = Field(min_length=1, max_length=200)


AdminType = Literal["ADMIN", "SUPER_ADMIN"]


class AdminItem(Model):
    id: str
    subject: str
    provisioner_id: str
    provisioner_name: str | None
    type: str
    created_at: datetime | None


class ProvisionerRef(Model):
    id: str
    name: str


class AdminList(Model):
    admins: list[AdminItem]
    # Only a SUPER_ADMIN may change admins on step-ca
    manageable: bool
    identity_type: str | None
    provisioners: list[ProvisionerRef]


class AdminCreate(BaseModel):
    subject: str = Field(min_length=1, max_length=400)
    provisioner: str = Field(min_length=1, max_length=200, description="The provisioner's name")
    type: AdminType


class AdminUpdate(BaseModel):
    type: AdminType


class Done(Model):
    message: str


# --- The CA and the system ------------------------------------------------------------------------------


class CaCertificate(Model):
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial: str
    key: str
    fingerprint: str
    days_left: int
    # Matches CA_FINGERPRINT: the app verifies the CA's TLS against it
    pinned: bool


class CrlInfo(Model):
    issuer: str
    entries: int
    this_update: datetime
    next_update: datetime | None


class CaStatus(Model):
    url: str
    health: str | None
    version: str | None
    version_tested: bool
    tested_versions: list[str]
    roots: list[CaCertificate] | None
    intermediates: list[CaCertificate] | None
    crl: CrlInfo | None
    errors: list[str]


class CrlQuery(BaseModel):
    format: Literal["der", "pem"] = "der"


class SettingItem(Model):
    label: str
    value: str


class SettingSection(Model):
    title: str
    items: list[SettingItem]


class SettingsView(Model):
    sections: list[SettingSection]
    warnings: list[str]


class AuditQuery(ListQuery):
    action: str | None = Field(None, max_length=100)
    success: bool | None = None


class AuditItem(Model):
    id: int
    created_at: datetime | None
    user: str
    role: str | None
    action: str
    target: str | None
    success: bool
    detail: str | None


class AuditPage(PageInfo):
    items: list[AuditItem]
    actions: list[str]


class SearchQuery(BaseModel):
    q: str = Field("", max_length=200)


class ProvisionerSummary(Model):
    id: str
    name: str
    type: str


class AdminSummary(Model):
    id: str
    subject: str
    provisioner_name: str | None
    type: str


class SearchResults(Model):
    query: str
    certificates: list[CertificateItem]
    acme_accounts: list[AcmeAccountItem]
    acme_orders: list[AcmeOrderItem]
    provisioners: list[ProvisionerSummary]
    admins: list[AdminSummary]
    # The kinds with more results than shown
    truncated: list[str]


class ServiceAction(BaseModel):
    action: Literal["start", "stop", "restart", "status"]


class ServiceResult(Model):
    success: bool
    output: str | None
    error: str | None
