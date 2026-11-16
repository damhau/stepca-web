"""The app itself: the configuration in effect, and the step-ca service control."""

import subprocess

from flask import current_app
from sqlalchemy.engine import make_url

from app.libs.audit import audit
from app.libs.auth.ldap_backend import ldap_transport
from app.services import ca, provisioners
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
    if config["OIDC_ENABLED"] and not (config["OIDC_ISSUER"] or "").lower().startswith("https://"):
        warnings.append("OIDC_ISSUER is not an https:// URL: tokens and the client secret cross the network unprotected.")
    return warnings


def effective_settings():
    """The configuration in effect, grouped for display. Secrets are never shown."""
    config = current_app.config
    settings = current_settings()
    sso = config["OIDC_ENABLED"]
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
                ("App identity type", provisioners.identity_type() or "unknown (CA unreachable or admin not found)"),
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
                ("Password sign-in", "enabled" if config["PASSWORD_LOGIN"] else "disabled"),
                ("Single sign-on", "enabled (OpenID Connect)" if sso else "disabled"),
                ("OIDC issuer", config["OIDC_ISSUER"] if sso else "—"),
                ("OIDC client ID", config["OIDC_CLIENT_ID"] if sso else "—"),
                ("OIDC client secret", ("set" if config["OIDC_CLIENT_SECRET"] else "not set") if sso else "—"),
                ("OIDC redirect URI", (config["OIDC_REDIRECT_URI"] or "from the request") if sso else "—"),
                ("OIDC claims", f"user: {config['OIDC_USERNAME_CLAIM']}, groups: {config['OIDC_GROUPS_CLAIM']}" if sso else "—"),
                ("OIDC required group", (config["OIDC_REQUIRED_GROUP"] or "—") if sso else "—"),
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


SERVICE_ACTIONS = ("start", "stop", "restart", "status")


def service_action(action):
    """Run the step-ca service control script through sudo: {"success", "output", "error"}. Audited, except status."""
    try:
        output = subprocess.check_output(["sudo", "/usr/local/bin/stepca_ctl.sh", action], stderr=subprocess.STDOUT, timeout=60)
        result = {"success": True, "output": output.decode(), "error": None}
    except subprocess.CalledProcessError as e:
        result = {"success": False, "output": None, "error": e.output.decode()}
    except (OSError, subprocess.TimeoutExpired) as e:
        result = {"success": False, "output": None, "error": f"Cannot run the service control script: {e}"}
    if action != "status":
        audit(f"service_{action}", "step-ca", success=result["success"], detail=result["error"] or "")
    return result
