from collections import Counter

from flask import render_template, request

from app.auth.decorator import login_required
from app.blueprint.home import bp
from app.libs.db_step import get_active_provisioner_map, get_step_provisioners
from app.libs.db_x509 import get_expiring_certs, get_revoked_x509_certs, get_x509_active_certs, get_x509_certs
from app.services import search as search_service
from app.stepca import store


@bp.route("/")
@login_required
def index():
    # The inventory is read once: every count and chart below comes from it
    certs = get_x509_certs()
    active_certs = get_x509_active_certs(certs)
    expiring_certs = get_expiring_certs(30, certs)
    revoked = get_revoked_x509_certs()
    provisioners = get_step_provisioners()
    active_provisioners = get_active_provisioner_map(provisioners)
    charts = {
        "issued_by_provisioner": dict(Counter(cert["provisioner"].get("name") or "Unknown" for cert in certs).most_common()),
        "acme_orders_by_status": dict(Counter((order.status or "unknown").lower() for order in store.acme_orders())),
    }

    return render_template(
        "home/index.html",
        total_certs=len(certs),
        active_certs=len(active_certs),
        expiring_certs=len(expiring_certs),
        acme_certs=store.acme_certificate_count(),
        revoked_certs=len(revoked),
        total_provisioners=len(active_provisioners),
        charts=charts,
    )


@bp.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    return render_template("search.html", title="Search", results=search_service.search(query))
