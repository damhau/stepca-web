"""SSH certificates (user and host): the list, filtered, sorted and paged, the counts of its tabs, and a certificate's page.

step-ca keeps SSH certificates in one table keyed by serial. Unlike the X.509 ones they are read in full for every
request: parsing a wire-format certificate is cheap, and libs.ssh_cert caches it by content."""

import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Literal

from app.libs import ssh_cert
from app.services import provisioners
from app.stepca import store
from app.stepca.records import Revocation, SshCertificate

SshStatus = Literal["valid", "expired", "not_yet_valid", "revoked", "invalid"]
SshKind = Literal["all", "user", "host"]
SshStatusFilter = Literal["all", "valid", "expired", "not_yet_valid", "revoked", "invalid"]
SshSortKey = Literal["valid_after", "valid_before", "key_id", "serial"]

_BEGINNING = datetime.min.replace(tzinfo=UTC)
_NEVER = datetime.max.replace(tzinfo=UTC)


def is_serial(text):
    """SSH certificates are identified by their decimal serial too (a 64-bit number)."""
    return text.isascii() and text.isdigit()


@dataclass(frozen=True)
class SshItem:
    """A row of the list: the certificate, and what its validity and the revocations make of it."""

    serial: str
    kind: str
    key_id: str
    principals: list[str]
    valid_after: datetime | None
    valid_before: datetime | None
    key_type: str
    fingerprint: str
    ca_fingerprint: str
    error: str | None
    status: SshStatus
    revoked_at: datetime | None
    revocation_reason: str | None
    revocation_reason_code: int | None


def status_of(cert: SshCertificate, revocation: Revocation | None, now: datetime) -> SshStatus:
    if cert.error:
        return "invalid"
    if revocation:
        return "revoked"
    if cert.valid_before and cert.valid_before <= now:
        return "expired"
    if cert.valid_after and cert.valid_after > now:
        return "not_yet_valid"
    return "valid"


def _item(cert: SshCertificate, revocation: Revocation | None, now: datetime) -> SshItem:
    return SshItem(
        serial=cert.serial,
        kind=cert.kind,
        key_id=cert.key_id,
        principals=cert.principals,
        valid_after=cert.valid_after,
        valid_before=cert.valid_before,
        key_type=cert.key_type,
        fingerprint=cert.fingerprint,
        ca_fingerprint=cert.ca_fingerprint,
        error=cert.error,
        status=status_of(cert, revocation, now),
        revoked_at=revocation.revoked_at if revocation else None,
        revocation_reason=(revocation.reason or None) if revocation else None,
        revocation_reason_code=revocation.reason_code if revocation else None,
    )


def items(now: datetime | None = None) -> list[SshItem]:
    """Every SSH certificate with its status."""
    now = now or datetime.now(UTC)
    revocations = store.ssh_revocations()
    return [_item(cert, revocations.get(cert.serial), now) for cert in store.ssh_certificates()]


@dataclass(frozen=True)
class SshQuery:
    kind: SshKind = "all"
    status: SshStatusFilter = "all"
    q: str = ""
    sort: SshSortKey = "valid_after"
    order: Literal["asc", "desc"] = "desc"


def _matches(item: SshItem, query: SshQuery) -> bool:
    if query.kind != "all" and item.kind != query.kind:
        return False
    if query.status != "all" and item.status != query.status:
        return False
    needle = query.q.strip().lower()
    return not needle or any(needle in value.lower() for value in (item.serial, item.key_id, item.fingerprint, *item.principals))


def _sort_key(sort: SshSortKey):
    # A certificate that never expires sorts after every other, one valid from the beginning before every other
    keys = {
        "valid_after": lambda item: item.valid_after or _BEGINNING,
        "valid_before": lambda item: item.valid_before or _NEVER,
        "key_id": lambda item: item.key_id.lower(),
        "serial": lambda item: int(item.serial),
    }
    return keys[sort]


def certificates(query: SshQuery, page=1, per_page: int | None = 50, now: datetime | None = None) -> tuple[list[SshItem], int]:
    """(this page of the matching certificates, how many match). per_page=None: all of them."""
    found = [item for item in items(now) if _matches(item, query)]
    found.sort(key=_sort_key(query.sort), reverse=query.order == "desc")
    if per_page is None:
        return found, len(found)
    start = (page - 1) * per_page
    return found[start : start + per_page], len(found)


def counts(kind: SshKind = "all", now: datetime | None = None) -> dict[str, int]:
    """How many certificates each tab of the list holds, of one kind (user or host) or of both."""
    found = [item for item in items(now) if kind == "all" or item.kind == kind]
    return {
        "all": len(found),
        "valid": sum(item.status == "valid" for item in found),
        "expired": sum(item.status == "expired" for item in found),
        "revoked": sum(item.status == "revoked" for item in found),
    }


@dataclass(frozen=True)
class Detail:
    """A certificate's page: its row, and what only the certificate itself says."""

    certificate: SshItem
    critical_options: list[dict]
    extensions: list[dict]
    revocation: dict | None
    # As in an id_*-cert.pub file: paste it there for `ssh-keygen -L -f`
    public_line: str


def detail(serial) -> Detail | None:
    """Everything about an SSH certificate, or None if step-ca has no such certificate."""
    if not is_serial(serial):
        return None
    cert = store.ssh_certificate(serial)
    blob = store.ssh_certificate_blob(serial)
    if cert is None or blob is None:
        return None
    revocation = store.ssh_revocations().get(serial)
    names = provisioners.names_by_id(include_deleted=True) if revocation else {}
    try:
        line = ssh_cert.public_line(blob)
    except ValueError:
        line = ""
    return Detail(
        certificate=_item(cert, revocation, datetime.now(UTC)),
        critical_options=[{"name": name, "value": value} for name, value in sorted(cert.critical_options.items())],
        extensions=[{"name": name, "value": value} for name, value in sorted(cert.extensions.items())],
        revocation={**asdict(revocation), "provisioner_name": names.get(revocation.provisioner_id)} if revocation else None,
        public_line=line,
    )


def download(serial):
    """(content, filename, content type) of an SSH certificate as an *-cert.pub file, or None if there is no such certificate."""
    blob = store.ssh_certificate_blob(serial) if is_serial(serial) else None
    if blob is None:
        return None
    try:
        line = ssh_cert.public_line(blob)
    except ValueError:
        return None
    try:
        key_id = ssh_cert.parse(blob).key_id
    except ValueError:
        key_id = serial  # a key type this app can't read can still be downloaded, and inspected with ssh-keygen -L
    name = re.sub(r"[^A-Za-z0-9._-]", "_", key_id) or serial
    return f"{line}\n".encode(), f"{name}-cert.pub", "text/plain; charset=utf-8"
