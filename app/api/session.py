"""Signing in and out. The session is Flask's signed cookie (HttpOnly, SameSite=Lax), as for the pages.

Two ways in: a username and a password (POST /session, checked by the LDAP or local backend), and single sign-on
with OpenID Connect (GET /session/oidc/login sends the browser to the provider, which sends it back to
GET /session/oidc/callback). Both end the same way: a fresh session with the user and their role.
"""

import logging
from urllib.parse import urlparse

from flask import current_app, redirect, request, session, url_for
from flask_wtf.csrf import generate_csrf

from app.api import blueprint, dump, error
from app.api.schemas import Error, LoginBody, OidcLoginQuery, SessionInfo
from app.auth.factory import get_auth_backend
from app.auth.roles import resolve_role
from app.extensions import limiter
from app.libs.audit import audit
from app.libs.auth.oidc import OIDCError
from app.settings import current_settings

log = logging.getLogger(__name__)

bp = blueprint("api_session", "Session")


def session_info():
    return dump(
        SessionInfo,
        {
            "authenticated": "user_id" in session,
            "user": session.get("user_id"),
            "role": session.get("role"),
            "csrf_token": generate_csrf(),
            "service_control": current_app.config["SERVICE_CONTROL_ENABLED"],
            "authority": authority(),
            "password_login": current_app.config["PASSWORD_LOGIN"],
            "sso_label": current_app.config["OIDC_DISPLAY_NAME"] if current_app.config["OIDC_ENABLED"] else None,
        },
    )


def authority():
    settings = current_settings()
    return {
        "name": settings.ca_display_name or urlparse(settings.ca_url).hostname or settings.ca_url,
        "environment": settings.ca_environment,
        "url": settings.ca_url,
    }


@bp.get("/session", responses={200: SessionInfo}, summary="Who is signed in, and the CSRF token")
def get_session():
    return session_info()


@bp.post("/session", responses={200: SessionInfo, 401: Error, 429: Error}, summary="Sign in")
# Only failed sign-ins count
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], deduct_when=lambda response: response.status_code == 401)
def login(body: LoginBody):
    backend = get_auth_backend(current_app.config)
    if backend is None:
        return error("Password sign-in is turned off: use single sign-on.", 403)
    user = backend.authenticate(body.username, body.password)
    role = resolve_role(user, current_app.config) if user else None
    if not (user and role):
        audit("login", body.username, success=False, detail="no role" if user else "invalid credentials", user=body.username)
        return error("Invalid username or password.", 401)
    start_session(user.get("id", body.username), role)
    audit("login", body.username)
    return session_info()


def start_session(user_id, role):
    # Start from an empty session: nothing set before sign-in survives it (nor its CSRF token)
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["role"] = role


def safe_next(value):
    """Only paths of this app: never a redirect to another site."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value and value.isprintable():
        return value
    return "/"


def redirect_uri():
    """What the provider has registered for this app: OIDC_REDIRECT_URI, else this request's own address."""
    return current_app.config["OIDC_REDIRECT_URI"] or url_for("api_session.oidc_callback", _external=True)


def failed_sso(reason, user=None, code="sso_failed"):
    """Back to the login page with a message that says nothing about why; the audit log and the log do."""
    log.warning("Single sign-on failed: %s", reason)
    audit("login", user or "-", success=False, detail=f"sso: {reason}", user=user or "-")
    response = redirect(f"/login?error={code}")
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/session/oidc/login", responses={302: None, 404: Error}, summary="Start single sign-on: redirects to the identity provider")
def oidc_login(query: OidcLoginQuery):
    client = current_app.extensions.get("oidc")
    if client is None:
        return error("Single sign-on is not enabled.", 404)
    try:
        url, pending = client.start(redirect_uri())
    except OIDCError as e:
        log.error("Cannot start single sign-on: %s", e)
        return redirect("/login?error=sso_unavailable")
    # Kept in the signed session cookie until the provider sends the browser back (SameSite=Lax allows that
    # top-level navigation)
    session["oidc"] = pending
    session["oidc_next"] = safe_next(query.next)
    response = redirect(url)
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/session/oidc/callback", responses={302: None, 404: Error}, summary="Where the identity provider sends the browser back to")
# Only failed sign-ins count, as for the password form
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], deduct_when=lambda response: "error=" in response.headers.get("Location", ""))
def oidc_callback():
    client = current_app.extensions.get("oidc")
    if client is None:
        return error("Single sign-on is not enabled.", 404)
    # Taken out of the session first: a state and a code are good for one try
    pending = session.pop("oidc", None)
    destination = safe_next(session.pop("oidc_next", None))
    try:
        user = client.finish(request.args, pending, redirect_uri())
    except OIDCError as e:
        return failed_sso(e)
    role = resolve_role(user, current_app.config)
    if not role:
        return failed_sso("no role", user["id"], code="no_access")
    start_session(user["id"], role)
    audit("login", user["id"], detail="sso")
    response = redirect(destination)
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.delete("/session", responses={200: SessionInfo}, summary="Sign out")
def logout():
    if "user_id" in session:
        audit("logout", session["user_id"])
    session.clear()
    return session_info()
