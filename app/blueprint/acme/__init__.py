from flask import Blueprint

bp = Blueprint('acme', __name__, url_prefix='/acme')
api_bp = Blueprint('acme_api', __name__, url_prefix='/api/acme')


from app.blueprint.acme import routes, api
