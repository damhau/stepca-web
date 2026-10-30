"""One search over certificates and ACME orders (the inventory), ACME accounts, provisioners and admins (step-ca's database)."""

from dataclasses import dataclass, field

from app.services import acme_inventory, inventory
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
    # The inventory matches the serial in decimal or hex, the subject and the DNS names
    certificates, total = inventory.certificates(inventory.CertificateQuery(q=needle), per_page=LIMIT)
    results.certificates = certificates
    if total > LIMIT:
        results.truncated.add("certificates")

    _limited(results, "acme_accounts", [a for a in store.acme_accounts() if _matches(needle, a.id, *a.contact)])
    # By id, account id or name (inventory.certificates above brought the copy up to date)
    orders, total = acme_inventory.orders(acme_inventory.ListQuery(q=needle, per_page=LIMIT))
    results.acme_orders = [order for order, _ in orders]
    if total > LIMIT:
        results.truncated.add("acme_orders")

    _limited(results, "provisioners", [p for p in store.provisioners() if _matches(needle, p.name)])
    _limited(results, "admins", [(admin, name) for admin, name in provisioner_service.search_admins() if _matches(needle, admin.subject)])
    return results
