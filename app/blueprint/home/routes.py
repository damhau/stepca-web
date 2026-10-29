from flask import render_template, request

from app.auth.decorator import login_required
from app.blueprint.home import bp
from app.services import dashboard
from app.services import search as search_service


@bp.route("/")
@login_required
def index():
    return render_template("home/index.html", summary=dashboard.summary())


@bp.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    return render_template("search.html", title="Search", results=search_service.search(query))
