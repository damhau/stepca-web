import logging
import os
import threading

from flask_openapi3 import Info, OpenAPI
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

from app.api.schemas import Error, ValidationProblem
from app.extensions import CONTENT_SECURITY_POLICY, csrf, db, limiter
from app.models.audit import AuditEvent  # noqa: F401  registers the model for create_all
from app.models.inventory import InventoryCertificate  # noqa: F401  registers the models (ACME ones too) for create_all
from app.models.x509 import GeneratedCert  # noqa: F401  registers the model for create_all
from app.services.inventory import InventoryState
from app.settings import Settings, load_settings
from app.stepca.client import StepCAClient

log = logging.getLogger(__name__)


def check_ldap_config(config):
    from app.libs.auth.ldap_backend import ldap_transport

    if config["LDAP_CA_FILE"] and not os.path.isfile(config["LDAP_CA_FILE"]):
        raise RuntimeError(f"LDAP_CA_FILE {config['LDAP_CA_FILE']} does not exist")
    if ldap_transport(config) == "cleartext":
        log.warning("LDAP_URL is ldap:// without LDAP_START_TLS: user passwords cross the network in cleartext. Use ldaps:// or set LDAP_START_TLS=true")


def warm_up_inventory(app):
    from sqlalchemy.exc import SQLAlchemyError

    from app.services import inventory

    with app.app_context():
        try:
            added = inventory.refresh(force=True)
            log.info("Inventory ready: %d certificates, revocations and ACME objects added", added)
        except SQLAlchemyError as e:
            log.warning("Cannot build the certificate inventory yet (it is built on the next page): %s", e)


def create_app(settings: Settings | None = None):
    """The app, from `settings` or else from the environment and settings.json (app.settings)."""
    settings = settings or load_settings()
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Flask, plus the OpenAPI document of the JSON API (app.api), built from its pydantic models
    from app.api import validation_error

    app = OpenAPI(
        __name__,
        # The frontend's files are served by app.web
        static_folder=None,
        info=Info(title="stepca-web", version="1"),
        # No documentation pages: the document is exported to frontend/openapi.json
        doc_ui=False,
        responses={401: Error},
        validation_error_model=ValidationProblem,
        validation_error_callback=validation_error,
    )
    app.config.update(settings.flask_config())
    app.extensions["settings"] = settings
    # The one CA client: one admin certificate, one decrypted admin key
    app.extensions["stepca"] = StepCAClient.from_settings(settings)
    app.extensions["inventory"] = InventoryState(refresh_seconds=settings.inventory_refresh_seconds)
    if app.config["AUTH_BACKEND"] == "ldap":
        check_ldap_config(app.config)

    if app.config["TRUSTED_PROXIES"]:
        # Behind reverse proxies: take the client address and scheme from their X-Forwarded-* headers
        proxies = app.config["TRUSTED_PROXIES"]
        # Flask's documented way to wrap the WSGI app; mypy sees a method being replaced
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxies, x_proto=proxies)  # type: ignore[method-assign]

    # Initialize Flask extensions here
    db.init_app(app)
    # Every POST/PUT/PATCH/DELETE must carry the session's CSRF token
    csrf.init_app(app)
    limiter.init_app(app)
    # Security headers. HTTPS is terminated by a reverse proxy, so no redirect to it here;
    # HSTS is only sent over HTTPS, and only when the UI is served over HTTPS (SESSION_COOKIE_SECURE)
    Talisman(
        app,
        force_https=False,
        strict_transport_security=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        frame_options="DENY",
        content_security_policy=CONTENT_SECURITY_POLICY,
        # A nonce per response, for the one style element the frontend adds (app.web)
        content_security_policy_nonce_in=["style-src"],
        referrer_policy="same-origin",
    )

    @app.route("/healthz")
    def healthz():
        """For container health checks: the app answers (it doesn't check the CA or the databases)."""
        return {"status": "ok"}

    # Every API route requires a session unless explicitly listed as public
    from app.auth.decorator import require_login

    app.before_request(require_login)

    if not app.testing:
        # Logs step-ca's version, and warns when it isn't one the app is tested with. In the background:
        # the app starts even when the CA is down
        from app.services.ca import check_ca_version

        threading.Thread(target=check_ca_version, args=(app.extensions["stepca"],), name="ca-version-check", daemon=True).start()

    with app.app_context():
        # Only the app's own SQLite tables: step-ca's database is never modified
        db.create_all(bind_key="app")

    if not app.testing:
        # Builds the certificate inventory, so that the first page doesn't wait for it
        threading.Thread(target=warm_up_inventory, args=(app,), name="inventory", daemon=True).start()


    from app import api, web

    api.register(app)
    # Last: its catch-all route serves the frontend for every other path
    app.register_blueprint(web.bp)

    return app
