"""The dashboard's counts and charts, from one read of the inventory."""

from collections import Counter
from dataclasses import dataclass, field

from app.services import certificates, provisioners
from app.stepca import store


@dataclass(frozen=True)
class Summary:
    total_certs: int
    active_certs: int
    expiring_certs: int
    acme_certs: int
    revoked_certs: int
    total_provisioners: int
    charts: dict = field(default_factory=dict)


def summary():
    inventory = certificates.all_certificates()
    issued_by = Counter((cert.provisioner.name if cert.provisioner and cert.provisioner.name else "Unknown") for cert in inventory)
    return Summary(
        total_certs=len(inventory),
        active_certs=len(certificates.active(inventory)),
        expiring_certs=len(certificates.expiring(30, inventory)),
        acme_certs=store.acme_certificate_count(),
        revoked_certs=len(store.revoked_serials()),
        total_provisioners=provisioners.count(),
        charts={
            "issued_by_provisioner": dict(issued_by.most_common()),
            "acme_orders_by_status": dict(Counter((order.status or "unknown").lower() for order in store.acme_orders())),
        },
    )
