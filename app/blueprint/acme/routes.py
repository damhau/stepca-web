from flask import render_template
from app.libs.db_acme import *
from app.blueprint.acme import bp


@bp.route("/accounts")
def accounts():
    accounts = get_acme_accounts()
    # print("Accounts:", accounts)
    return render_template("acme/accounts.html", title="ACME Accounts", accounts=accounts)

@bp.route("/orders")
def orders():
    orders = get_acme_orders()
    return render_template("acme/orders.html", title="ACME Orders", orders=orders)

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