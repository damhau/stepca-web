"""One search over certificates, ACME accounts and orders, provisioners and admins (step-ca's database only)."""

import re
from dataclasses import dataclass, field

from app.services import provisioners as provisioner_service
from app.stepca import store

# Results shown per kind; the page says when there are more
LIMIT = 50


@dataclass
class Results:
    query: str
    certificates: list = field(default_factory=list)
    acme_accounts: list = field(default_factory=list)
    acme_orders: list = field(default_factory=list)
    provisioners: list = field(default_factory=list)
    admins: list = field(default_factory=list)
    truncated: set = field(default_factory=set)

    @property
    def count(self):
        return sum(len(getattr(self, kind)) for kind in ("certificates", "acme_accounts", "acme_orders", "provisioners", "admins"))


def hex_serial(text):
    """A hex serial as people paste it (colons, spaces, 0x, any case), as cert_utils writes it; None if it isn't hex."""
    compact = re.sub(r"[\s:]", "", text.lower()).removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]+", compact):
        return None
    return compact.lstrip("0") or "0"


def _matches(needle, *values):
    return any(needle in (value or "").lower() for value in values)


def _limited(results, kind, matches):
    if len(matches) > LIMIT:
        results.truncated.add(kind)
    setattr(results, kind, matches[:LIMIT])


def search(query):
    needle = query.strip().lower()
    results = Results(query=query.strip())
    if len(needle) < 2:
        return results
    hex_needle = hex_serial(needle)

    certificates = [
        cert
        for cert in store.certificates()
        if _matches(needle, cert.serial, cert.subject, *cert.dns_names) or (hex_needle and hex_needle in cert.serial_hex)
    ]
    _limited(results, "certificates", certificates)

    _limited(results, "acme_accounts", [a for a in store.acme_accounts() if _matches(needle, a.id, *a.contact)])
    _limited(results, "acme_orders", [o for o in store.acme_orders() if _matches(needle, o.id, *(i.value for i in o.identifiers))])

    _limited(results, "provisioners", [p for p in store.provisioners() if _matches(needle, p.name)])
    _limited(results, "admins", [(admin, name) for admin, name in provisioner_service.search_admins() if _matches(needle, admin.subject)])
    return results
