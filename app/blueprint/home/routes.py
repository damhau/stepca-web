from collections import Counter

from flask import render_template

from app.auth.decorator import login_required
from app.blueprint.home import bp
from app.libs.db_acme import get_acme_certs, get_acme_orders
from app.libs.db_step import get_active_provisioner_map, get_step_provisioners
from app.libs.db_x509 import get_expiring_certs, get_revoked_x509_certs, get_x509_active_certs, get_x509_certs


@bp.route("/")
@login_required
def index():
    # The inventory is read once: every count and chart below comes from it
    certs = get_x509_certs()
    active_certs = get_x509_active_certs(certs)
    expiring_certs = get_expiring_certs(30, certs)
    acme_certs = get_acme_certs()
    revoked = get_revoked_x509_certs()
    provisioners = get_step_provisioners()
    active_provisioners = get_active_provisioner_map(provisioners)
    charts = {
        "issued_by_provisioner": dict(Counter(cert["provisioner"].get("name") or "Unknown" for cert in certs).most_common()),
        "acme_orders_by_status": dict(Counter((order["data"].get("status") or "unknown").lower() for order in get_acme_orders())),
    }

    return render_template(
        "home/index.html",
        total_certs=len(certs),
        active_certs=len(active_certs),
        expiring_certs=len(expiring_certs),
        acme_certs=len(acme_certs),
        revoked_certs=len(revoked),
        total_provisioners=len(active_provisioners),
        charts=charts,
    )
