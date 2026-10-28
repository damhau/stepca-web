from flask import render_template

from app.blueprint.acme import bp
from app.libs.db_acme import *


@bp.route("/accounts")
def accounts():
    accounts = get_acme_accounts()
    # print("Accounts:", accounts)
    return render_template("acme/accounts.html", title="ACME Accounts", accounts=accounts)

@bp.route("/orders")
def orders():
    orders = get_acme_orders()
    # ACME certificate id -> decimal serial, to link each order to its certificate's page
    cert_serials = {c["data"].get("id"): c["data"].get("serial_dec") for c in get_acme_certs()}
    return render_template("acme/orders.html", title="ACME Orders", orders=orders, cert_serials=cert_serials)

@bp.route("/certs")
def certs():
    certs = get_acme_certs()
    return render_template("acme/certs.html", title="ACME Certificates", certs=certs)

@bp.route("/authzs")
def authzs():
    authzs = get_acme_authzs()
    return render_template("acme/authzs.html", title="ACME Authorizations", authzs=authzs)

@bp.route("/challenges")
def challenges():
    challenges = get_acme_challenges()
    return render_template("acme/challenges.html", title="ACME Challenges", challenges=challenges)