from flask import Blueprint

bp = Blueprint('acme', __name__, url_prefix='/acme')


from app.blueprint.acme import routes
