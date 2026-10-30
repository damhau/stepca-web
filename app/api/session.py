"""Signing in and out. The session is Flask's signed cookie (HttpOnly, SameSite=Lax), as for the pages."""

from urllib.parse import urlparse

from flask import current_app, session
from flask_wtf.csrf import generate_csrf

from app.api import blueprint, dump, error
from app.api.schemas import Error, LoginBody, SessionInfo
from app.auth.factory import get_auth_backend
from app.auth.roles import resolve_role
from app.extensions import limiter
from app.libs.audit import audit
from app.settings import current_settings

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
    user = get_auth_backend(current_app.config).authenticate(body.username, body.password)
    role = resolve_role(user, current_app.config) if user else None
    if not (user and role):
        audit("login", body.username, success=False, detail="no role" if user else "invalid credentials", user=body.username)
        return error("Invalid username or password.", 401)
    # Start from an empty session: nothing set before sign-in survives it (nor its CSRF token)
    session.clear()
    session.permanent = True
    session["user_id"] = user.get("id", body.username)
    session["role"] = role
    audit("login", body.username)
    return session_info()


@bp.delete("/session", responses={200: SessionInfo}, summary="Sign out")
def logout():
    if "user_id" in session:
        audit("logout", session["user_id"])
    session.clear()
    return session_info()
