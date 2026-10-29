"""The dashboard's counts and charts."""

from collections import Counter

from app.services import inventory, provisioners
from app.stepca import store


def overview():
    """Counts from the inventory, in SQL; ACME orders from step-ca's table."""
    counts = inventory.counts(expiring_days=30)
    soonest, _ = inventory.certificates(inventory.CertificateQuery(status="expiring", days=30, sort="not_after", order="asc"), per_page=5)
    orders = Counter((order.status or "unknown").lower() for order in store.acme_orders())
    return {
        "total": counts.total,
        "valid": counts.valid,
        "expiring": counts.expiring,
        "expired": counts.expired,
        "revoked": counts.revoked,
        "acme_certificates": store.acme_certificate_count(),
        "provisioners": provisioners.count(),
        "issued_by_provisioner": [{"name": name, "count": count} for name, count in counts.by_provisioner],
        "acme_orders_by_status": [{"name": status, "count": count} for status, count in orders.most_common()],
        "expiring_soon": soonest,
        "pending": inventory.pending(),
    }
