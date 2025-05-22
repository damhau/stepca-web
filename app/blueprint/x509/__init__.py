from flask import Blueprint

bp = Blueprint('x509', __name__, url_prefix='/x509')
api_bp = Blueprint('x509_api', __name__, url_prefix='/api/x509')


from app.blueprint.x509 import routes, api


