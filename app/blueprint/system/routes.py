from flask import current_app, render_template
from sqlalchemy.engine import make_url

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.system import bp
from app.libs import ca
from app.libs.audit import recent_events
from app.libs.auth.ldap_backend import ldap_transport
from app.settings import current_settings

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
    settings = current_settings()
    return [
        (
            "Step CA database (read-only)",
            [
                ("Host", settings.database_host),
                ("Port", settings.database_port),
                ("Database", settings.database_name),
                ("User", settings.database_user),
                ("Password", "set" if settings.database_password else "not set"),
            ],
        ),
        (
            "Step CA",
            [
                ("URL", settings.ca_url),
                ("Root fingerprint", settings.ca_fingerprint or "not set"),
                ("Root certificate", str(settings.ca_root) if settings.ca_root else "downloaded from the CA and pinned with the fingerprint"),
                ("App identity", f"{settings.ca_admin_subject} on provisioner {settings.ca_admin_provisioner_name}"),
                ("App identity type", ca.app_identity_type() or "unknown (CA unreachable or admin not found)"),
                ("Admin provisioner key", ca.client().admin_key_source()),
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
                ("Data directory", str(settings.data_dir.resolve())),
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
