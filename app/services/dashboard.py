"""The dashboard's counts and charts."""

from app.services import acme_inventory, inventory, provisioners
from app.stepca import store


def overview():
    """Counts from the inventory and its copy of the ACME orders, in SQL."""
    counts = inventory.counts(expiring_days=30)
    soonest, _ = inventory.certificates(inventory.CertificateQuery(status="expiring", days=30, sort="not_after", order="asc"), per_page=5)
    return {
        "total": counts.total,
        "valid": counts.valid,
        "expiring": counts.expiring,
        "expired": counts.expired,
        "revoked": counts.revoked,
        "acme_certificates": store.acme_certificate_count(),
        "provisioners": provisioners.count(),
        "issued_by_provisioner": [{"name": name, "count": count} for name, count in counts.by_provisioner],
        "acme_orders_by_status": [{"name": status, "count": count} for status, count in acme_inventory.orders_by_status()],
        "expiring_soon": soonest,
        "pending": inventory.pending(),
    }
