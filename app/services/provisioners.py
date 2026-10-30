"""Provisioners and admins.

step-ca shows them two ways: its Admin API, the authority's live configuration with every setting, and its
database. The pages list and change what the Admin API returns. The database only fills in what the API
leaves out: provisioner ids (absent from its provisioner list), admins' creation dates (absent for admins
added since the CA started), and the provisioner lists of pages that don't call the CA.
"""

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from app.libs.provisioners import ACME_CHALLENGES
from app.services import ca
from app.stepca import store

# How long the app's admin type (ADMIN / SUPER_ADMIN) is cached
IDENTITY_CACHE_SECONDS = 300


def names_by_id(include_deleted=False):
    return {p.id: p.name for p in store.provisioners(include_deleted=include_deleted)}


def count():
    return len(store.provisioners())


def signing_provisioners():
    """JWK provisioners: the only ones that sign a CSR with a password."""
    return sorted(p.name for p in store.provisioners() if p.type == "JWK")


def identity_type():
    """'SUPER_ADMIN' or 'ADMIN' for the app's own admin on the CA, None if unknown. Cached on the client.

    The Admin API lists admins with a provisioner id but provisioners without one: names come from the database.
    """
    client = ca.client()
    # -inf at first, not 0: time.monotonic() counts from boot, so it can be under the cache lifetime
    fetched_at, admin_type = client.identity_cache
    if time.monotonic() - fetched_at < IDENTITY_CACHE_SECONDS:
        return admin_type
    admin_type = None
    listed = client.list_admins()
    if listed:
        names = names_by_id()
        for admin in listed["admins"]:
            if admin.get("subject") == client.subject and names.get(admin.get("provisioner_id")) == client.provisioner_name:
                admin_type = store.ADMIN_TYPES.get(admin.get("type"), admin.get("type"))
    client.identity_cache = (time.monotonic(), admin_type)
    return admin_type


def admins_manageable():
    """Only a SUPER_ADMIN may change admins on step-ca: with an ADMIN identity they are read-only."""
    return identity_type() == "SUPER_ADMIN"


@dataclass(frozen=True)
class AdminRow:
    id: str
    subject: str
    provisioner_id: str
    provisioner_name: str | None
    type: str
    created_at: datetime | None
    # What the Admin API returned, for the edit dialog
    raw: dict


def admin_rows(listed):
    """The Admin API's admins, with provisioner names and creation dates from the database."""
    names = names_by_id()
    created = {admin.id: admin.created_at for admin in store.admins(include_deleted=True)}
    rows = []
    for admin in listed:
        seconds = (admin.get("created_at") or {}).get("seconds")
        rows.append(
            AdminRow(
                id=admin.get("id", ""),
                subject=admin.get("subject", ""),
                provisioner_id=admin.get("provisioner_id", ""),
                provisioner_name=names.get(admin.get("provisioner_id")),
                type=store.ADMIN_TYPES.get(admin.get("type"), str(admin.get("type"))),
                created_at=datetime.fromtimestamp(seconds, UTC) if seconds else created.get(admin.get("id")),
                raw=admin,
            )
        )
    return rows


def search_admins():
    """Admins from the database, with their provisioner's name, for the search page (no CA call)."""
    names = names_by_id()
    return [(admin, names.get(admin.provisioner_id)) for admin in store.admins()]


# The list (GET /admin/provisioners) has step-ca's older JSON: claims as "maxTLSCertDuration" and the like, ACME
# settings at the top. A single provisioner (GET /admin/provisioners/{name}) is linkedca's protobuf JSON.
LIST_CHALLENGES = {value: name for name, value in ACME_CHALLENGES}


def _durations(claims):
    linked = (claims.get("x509") or {}).get("durations")
    if linked is not None:
        return linked
    listed = {
        "min": claims.get("minTLSCertDuration"),
        "default": claims.get("defaultTLSCertDuration"),
        "max": claims.get("maxTLSCertDuration"),
    }
    return {key: value for key, value in listed.items() if value}


def _acme(provisioner):
    linked = (provisioner.get("details") or {}).get("ACME")
    if linked is not None:
        challenges, require_eab, force_cn = linked.get("challenges", []), linked.get("requireEab"), linked.get("forceCn")
    else:
        challenges = [LIST_CHALLENGES.get(c, c) for c in provisioner.get("challenges") or []]
        require_eab, force_cn = provisioner.get("requireEAB"), provisioner.get("forceCN")
    return {
        # Only the ones the forms offer
        "challenges": [c for c in challenges if c in {name for name, _ in ACME_CHALLENGES}],
        "require_eab": bool(require_eab),
        "force_cn": bool(force_cn),
    }


def summary(provisioner, ids_by_name=None, app_provisioner=None, issued=None, ca_url=None, created=None):
    """A provisioner as either Admin API call returns it, with its settings the forms show."""
    claims = provisioner.get("claims") or {}
    name = provisioner.get("name", "")
    created_at = provisioner.get("createdAt")
    return {
        "name": name,
        "type": provisioner.get("type", ""),
        "id": provisioner.get("id") or (ids_by_name or {}).get(name),
        "durations": _durations(claims),
        "disable_renewal": bool(claims.get("disableRenewal")),
        "allow_renewal_after_expiry": bool(claims.get("allowRenewalAfterExpiry")),
        "acme": _acme(provisioner) if provisioner.get("type") == "ACME" else None,
        "created_at": store.go_time(created_at) if isinstance(created_at, str) else (created or {}).get(name),
        "is_app_provisioner": name == app_provisioner,
        "directory_url": f"{ca_url.rstrip('/')}/acme/{quote(name, safe='')}/directory"
        if ca_url and provisioner.get("type") == "ACME"
        else None,
        "issued_30d": (issued or {}).get(name, 0),
        "raw": provisioner,
    }


def summaries(listed):
    from app.services import inventory

    stored = store.provisioners()
    ids_by_name = {p.name: p.id for p in stored}
    created = {p.name: p.created_at for p in stored}
    client = ca.client()
    inventory.refresh()
    when = datetime.now(UTC)
    issued = inventory.issued_by_provisioner(when - timedelta(days=30), when)
    return [summary(provisioner, ids_by_name, client.provisioner_name, issued, client.ca_url, created) for provisioner in listed]
