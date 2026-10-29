from flask import current_app, render_template
from sqlalchemy.engine import make_url

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.system import bp
from app.libs import ca
from app.libs.audit import recent_events
from app.libs.auth.ldap_backend import ldap_transport
from config import (
    CA_ADMIN_PROVISIONER_NAME,
    CA_ADMIN_SUBJECT,
    CA_FINGERPRINT,
    CA_ROOT,
    CA_URL,
    DB_HOST,
    DB_NAME,
    DB_PASSWORD,
    DB_PORT,
    DB_USER,
)

LDAP_TRANSPORTS = {
    "ldaps": "LDAPS, server certificate verified",
    "starttls": "StartTLS, server certificate verified",
    "cleartext": "cleartext: passwords are readable on the network",
}


def config_warnings():
    config = current_app.config
    warnings = []
    if config["AUTH_BACKEND"] == "ldap" and ldap_transport(config) == "cleartext":
        warnings.append("LDAP passwords cross the network in cleartext: use an ldaps:// LDAP_URL or set LDAP_START_TLS=true.")
    return warnings


def effective_settings():
    """The configuration in effect, grouped for display. Secrets are never shown."""
    config = current_app.config
    return [
        (
            "Step CA database (read-only)",
            [
                ("Host", DB_HOST),
                ("Port", DB_PORT),
                ("Database", DB_NAME),
                ("User", DB_USER),
                ("Password", "set" if DB_PASSWORD else "not set"),
            ],
        ),
        (
            "Step CA",
            [
                ("URL", CA_URL),
                ("Root fingerprint", CA_FINGERPRINT or "not set"),
                ("Root certificate", CA_ROOT or "downloaded from the CA and pinned with the fingerprint"),
                ("App identity", f"{CA_ADMIN_SUBJECT} on provisioner {CA_ADMIN_PROVISIONER_NAME}"),
                ("App identity type", ca.app_identity_type() or "unknown (CA unreachable or admin not found)"),
                ("Admin provisioner key", ca.client.admin_key_source()),
            ],
        ),
        (
            "Authentication",
            [
                ("Backend", config["AUTH_BACKEND"]),
                ("LDAP URL", config["LDAP_URL"] if config["AUTH_BACKEND"] == "ldap" else "—"),
                ("LDAP transport", LDAP_TRANSPORTS[ldap_transport(config)] if config["AUTH_BACKEND"] == "ldap" else "—"),
                ("LDAP CA file", (config["LDAP_CA_FILE"] or "system CAs") if config["AUTH_BACKEND"] == "ldap" else "—"),
                ("Admin group", config["ROLE_ADMIN_GROUP"] or "—"),
                ("Operator group", config["ROLE_OPERATOR_GROUP"] or "—"),
                ("Viewer group", config["ROLE_VIEWER_GROUP"] or "—"),
                ("Default role", config["DEFAULT_ROLE"]),
                ("Session lifetime", str(config["PERMANENT_SESSION_LIFETIME"])),
            ],
        ),
        (
            "Application",
            [
                ("App database", make_url(config["SQLALCHEMY_BINDS"]["app"]).render_as_string(hide_password=True)),
                ("Service control", "enabled" if config["SERVICE_CONTROL_ENABLED"] else "disabled"),
            ],
        ),
    ]


@bp.route("/config")
@login_required
@role_required("admin")
def config():
    return render_template("system/config.html", title="Configuration", settings=effective_settings(), warnings=config_warnings())


@bp.route("/audit")
@login_required
@role_required("admin")
def audit_log():
    return render_template("system/audit.html", title="Audit Log", events=recent_events())
