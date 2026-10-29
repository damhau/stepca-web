"""The certificate inventory: step-ca's certificates and revocations, parsed once into the app's database.

Neither ever changes once step-ca has written it, so keeping the inventory current only means adding the
rows that are new in step-ca's tables. Every read checks for them, at most every INVENTORY_REFRESH_SECONDS:
two row counts when nothing changed, the table keys when something did, then only the new rows are parsed.
"""

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from flask import current_app
from sqlalchemy import and_, asc, delete, desc, func, insert, or_, select

from app.extensions import db
from app.models.inventory import InventoryCertificate, InventoryRevocation
from app.stepca import store
from app.stepca.records import Certificate, Revocation

log = logging.getLogger(__name__)

# Rows parsed and written per transaction
BATCH = 500
# Even when the counts match, compare the keys this often: a row deleted by hand and one added would cancel out
FULL_CHECK_SECONDS = 300

Status = Literal["valid", "expired", "not_yet_valid", "revoked", "invalid"]
StatusFilter = Literal["all", "valid", "expiring", "expired", "not_yet_valid", "revoked"]
SortKey = Literal["not_after", "not_before", "subject", "serial", "provisioner"]


@dataclass
class InventoryState:
    """Per app: when the inventory was last checked, and the lock that lets one thread refresh it at a time."""

    refresh_seconds: float
    lock: threading.Lock = field(default_factory=threading.Lock)
    # -inf, not 0: time.monotonic() counts from boot
    checked_at: float = float("-inf")
    full_check_at: float = float("-inf")


def _state() -> InventoryState:
    return current_app.extensions["inventory"]


def now():
    return datetime.now(UTC)


def _naive_utc(value):
    return value.astimezone(UTC).replace(tzinfo=None) if value else None


def _aware(value):
    return value.replace(tzinfo=UTC) if value else None


def _key(cert: Certificate):
    if isinstance(cert.key, int):
        return f"RSA {cert.key}"
    return cert.key or ""


def _common_name(subject):
    for part in subject.split(","):
        if part.startswith("CN="):
            return part[3:]
    return None


def _certificate_row(cert: Certificate):
    provisioner = cert.provisioner
    return {
        "serial": cert.serial,
        "serial_hex": cert.serial_hex,
        "subject": cert.subject,
        "common_name": _common_name(cert.subject),
        "issuer": cert.issuer,
        "not_before": _naive_utc(cert.not_before),
        "not_after": _naive_utc(cert.not_after),
        "key": _key(cert),
        "dns_names": list(cert.dns_names),
        "provisioner_id": provisioner.id if provisioner else None,
        "provisioner_name": provisioner.name if provisioner else None,
        "provisioner_type": provisioner.type if provisioner else None,
        "error": cert.error,
        "search": " ".join([cert.serial, cert.serial_hex, cert.subject, *cert.dns_names]).lower(),
    }


def _revocation_row(revocation: Revocation):
    return {
        "serial": revocation.serial,
        "reason_code": revocation.reason_code,
        "reason": revocation.reason,
        "revoked_at": _naive_utc(revocation.revoked_at),
        "provisioner_id": revocation.provisioner_id,
        "mtls": revocation.mtls,
        "acme": revocation.acme,
    }


def _insert_new(model, rows):
    """Insert rows, skipping those another worker inserted in the meantime."""
    if not rows:
        return
    from sqlalchemy.dialects import postgresql, sqlite

    dialect = db.session.get_bind(mapper=model.__mapper__).dialect.name
    if dialect == "sqlite":
        db.session.execute(sqlite.insert(model).on_conflict_do_nothing(), rows)
    elif dialect == "postgresql":
        db.session.execute(postgresql.insert(model).on_conflict_do_nothing(), rows)
    else:
        db.session.execute(insert(model), rows)


def _chunks(items, size):
    items = sorted(items)
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _sync(model, step_count, step_keys, read, to_row, full):
    """Add step-ca's new rows to `model`, drop those step-ca no longer has. Returns the number added."""
    cached_count = db.session.scalar(select(func.count()).select_from(model))
    if cached_count == step_count and not full:
        return 0
    wanted = step_keys()
    cached = set(db.session.scalars(select(model.serial)))
    gone = cached - wanted
    for batch in _chunks(gone, BATCH):
        db.session.execute(delete(model).where(model.serial.in_(batch)))
    new = wanted - cached
    for batch in _chunks(new, BATCH):
        _insert_new(model, [to_row(record) for record in read(batch)])
        db.session.commit()
    db.session.commit()
    if new or gone:
        log.info("Inventory %s: %d added, %d removed", model.__tablename__, len(new), len(gone))
    return len(new)


def refresh(force=False):
    """Bring the inventory up to date with step-ca's tables. Returns the number of rows added.

    Skipped when it was checked less than INVENTORY_REFRESH_SECONDS ago (unless `force`), or while another
    thread is refreshing it: readers then see the inventory as it is.
    """
    state = _state()
    started = time.monotonic()
    if not force and started - state.checked_at < state.refresh_seconds:
        return 0
    if not state.lock.acquire(blocking=False):
        return 0
    try:
        full = force or started - state.full_check_at > FULL_CHECK_SECONDS
        added = _sync(InventoryCertificate, store.certificate_count(), store.certificate_serials, store.certificates, _certificate_row, full)
        added += _sync(InventoryRevocation, store.revocation_count(), store.revoked_serials, store.revocations, _revocation_row, full)
        state.checked_at = started
        if full:
            state.full_check_at = started
        return added
    finally:
        state.lock.release()


def pending():
    """Certificates step-ca has that the inventory doesn't have yet (while it is being built)."""
    cached = db.session.scalar(select(func.count()).select_from(InventoryCertificate))
    return max(store.certificate_count() - cached, 0)


# --- Reading --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class InventoryItem:
    serial: str
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


def status_of(not_before, not_after, revoked, when):
    if revoked:
        return "revoked"
    if not_before is None or not_after is None:
        return "invalid"
    if not_after < when:
        return "expired"
    if not_before > when:
        return "not_yet_valid"
    return "valid"


def _item(cert: InventoryCertificate, revocation: InventoryRevocation | None, when):
    not_before, not_after = _aware(cert.not_before), _aware(cert.not_after)
    return InventoryItem(
        serial=cert.serial,
        serial_hex=cert.serial_hex,
        subject=cert.subject,
        common_name=cert.common_name,
        issuer=cert.issuer,
        not_before=not_before,
        not_after=not_after,
        key=cert.key,
        dns_names=list(cert.dns_names or []),
        provisioner_id=cert.provisioner_id,
        provisioner_name=cert.provisioner_name,
        provisioner_type=cert.provisioner_type,
        error=cert.error,
        status=status_of(not_before, not_after, revocation is not None, when),
        days_left=(not_after - when).days if not_after else None,
        revoked_at=_aware(revocation.revoked_at) if revocation else None,
        revocation_reason=revocation.reason if revocation else None,
        revocation_reason_code=revocation.reason_code if revocation else None,
    )


@dataclass(frozen=True)
class CertificateQuery:
    status: StatusFilter = "all"
    # For status "expiring": expires within this many days
    days: int = 30
    q: str = ""
    provisioner: str | None = None
    sort: SortKey = "not_before"
    order: Literal["asc", "desc"] = "desc"


SORT_COLUMNS = {
    "not_after": InventoryCertificate.not_after,
    "not_before": InventoryCertificate.not_before,
    "subject": InventoryCertificate.subject,
    "serial": InventoryCertificate.serial,
    "provisioner": InventoryCertificate.provisioner_name,
}


def _like(text):
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def hex_serial(text):
    """A hex serial as people paste it (colons, spaces, 0x, any case), as cert_utils writes it; None if it isn't hex."""
    compact = re.sub(r"[\s:]", "", text.lower()).removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]+", compact):
        return None
    return compact.lstrip("0") or "0"


def _filtered(query: CertificateQuery, when):
    statement = select(InventoryCertificate, InventoryRevocation).outerjoin(
        InventoryRevocation, InventoryRevocation.serial == InventoryCertificate.serial
    )
    cert, revoked = InventoryCertificate, InventoryRevocation.serial.is_not(None)
    naive_now = _naive_utc(when)
    valid = and_(~revoked, cert.not_before <= naive_now, cert.not_after >= naive_now)
    conditions = {
        "valid": valid,
        "expiring": and_(valid, cert.not_after < _naive_utc(when + timedelta(days=query.days))),
        "expired": and_(~revoked, cert.not_after < naive_now),
        "not_yet_valid": and_(~revoked, cert.not_before > naive_now),
        "revoked": revoked,
    }
    if query.status in conditions:
        statement = statement.where(conditions[query.status])
    needle = query.q.strip().lower()
    if needle:
        matches = [cert.search.like(_like(needle), escape="\\")]
        if hex_needle := hex_serial(needle):
            matches.append(cert.serial_hex.like(_like(hex_needle), escape="\\"))
        statement = statement.where(or_(*matches))
    if query.provisioner:
        statement = statement.where(cert.provisioner_name == query.provisioner)
    return statement


def certificates(query: CertificateQuery, page=1, per_page=50):
    """(items of this page, total matching). per_page None: every matching certificate."""
    refresh()
    when = now()
    statement = _filtered(query, when)
    total = db.session.scalar(select(func.count()).select_from(statement.subquery()))
    direction = asc if query.order == "asc" else desc
    statement = statement.order_by(direction(SORT_COLUMNS[query.sort]).nulls_last(), InventoryCertificate.serial)
    if per_page is not None:
        statement = statement.limit(per_page).offset((page - 1) * per_page)
    return [_item(cert, revocation, when) for cert, revocation in db.session.execute(statement)], total


def certificate(serial):
    refresh()
    row = db.session.execute(
        select(InventoryCertificate, InventoryRevocation)
        .outerjoin(InventoryRevocation, InventoryRevocation.serial == InventoryCertificate.serial)
        .where(InventoryCertificate.serial == serial)
    ).first()
    return _item(row[0], row[1], now()) if row else None


@dataclass(frozen=True)
class Counts:
    total: int
    valid: int
    expiring: int
    expired: int
    revoked: int
    by_provisioner: list[tuple[str, int]]


def counts(expiring_days=30):
    refresh()
    when = now()

    def count(status):
        return db.session.scalar(select(func.count()).select_from(_filtered(CertificateQuery(status=status, days=expiring_days), when).subquery()))

    name = func.coalesce(InventoryCertificate.provisioner_name, "Unknown")
    by_provisioner = db.session.execute(select(name, func.count()).group_by(name).order_by(func.count().desc(), name)).all()
    return Counts(
        total=count("all"),
        valid=count("valid"),
        expiring=count("expiring"),
        expired=count("expired"),
        # Every revocation, including those of serials step-ca never issued (see certificates.misdirected_serial)
        revoked=db.session.scalar(select(func.count()).select_from(InventoryRevocation)) or 0,
        by_provisioner=[(provisioner, total) for provisioner, total in by_provisioner],
    )


def provisioner_names():
    """The provisioners that issued certificates, for the list's filter."""
    refresh()
    return list(db.session.scalars(select(InventoryCertificate.provisioner_name).where(InventoryCertificate.provisioner_name.is_not(None)).distinct().order_by(InventoryCertificate.provisioner_name)))
