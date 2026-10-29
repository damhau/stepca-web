from flask import flash, redirect, render_template, url_for

from app.blueprint.acme import bp
from app.services import acme


@bp.route("/accounts")
def accounts():
    return render_template("acme/accounts.html", title="ACME Accounts", accounts=acme.accounts())


@bp.route("/account/<account_id>")
def account(account_id):
    found = acme.account(account_id)
    if found is None:
        flash(f"ACME account {account_id} not found", "danger")
        return redirect(url_for("acme.accounts"))
    account, orders = found
    return render_template("acme/account.html", title=f"ACME account {account_id}", account=account, orders=orders)


@bp.route("/orders")
def orders():
    return render_template("acme/orders.html", title="ACME Orders", orders=acme.orders())


@bp.route("/order/<order_id>")
def order(order_id):
    view = acme.order(order_id)
    if view is None:
        flash(f"ACME order {order_id} not found", "danger")
        return redirect(url_for("acme.orders"))
    return render_template("acme/order.html", title=f"ACME order {order_id}", view=view)


@bp.route("/certs")
def certs():
    return render_template("acme/certs.html", title="ACME Certificates", certs=acme.certificates())


@bp.route("/authzs")
def authzs():
    return render_template("acme/authzs.html", title="ACME Authorizations", authzs=acme.authorizations())


@bp.route("/challenges")
def challenges():
    return render_template("acme/challenges.html", title="ACME Challenges", challenges=acme.challenges())
