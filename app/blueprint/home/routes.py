from flask import render_template
from app.blueprint.home import bp
from app.libs.db_x509 import *
from app.libs.db_acme import *
from app.libs.db_step import *
from app.auth.decorator import login_required

@bp.route("/")
@login_required
def index():
    certs = get_x509_certs()
    active_certs = get_x509_active_certs()
    acme_certs = get_acme_certs()
    revoked = get_revoked_x509_certs()
    provisioners = get_step_provisioners()
    active_provisioners = get_active_provisioner_map(provisioners)

    return render_template(
        "home/index.html",
        total_certs=len(certs),
        active_certs=len(active_certs),
        acme_certs=len(acme_certs),
        revoked_certs=len(revoked),
        total_provisioners=len(active_provisioners),
    )

