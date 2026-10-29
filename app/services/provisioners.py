"""Provisioners and admins.

step-ca shows them two ways: its Admin API, the authority's live configuration with every setting, and its
database. The pages list and change what the Admin API returns. The database only fills in what the API
leaves out: provisioner ids (absent from its provisioner list), admins' creation dates (absent for admins
added since the CA started), and the provisioner lists of pages that don't call the CA.
"""

import time
from dataclasses import dataclass
from datetime import UTC, datetime

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
