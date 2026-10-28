from flask import Blueprint

bp = Blueprint('home', __name__)


from app.blueprint.home import routes  # noqa: E402, F401  registers the routes on the blueprint
