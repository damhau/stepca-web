from flask import jsonify, request, session

# API endpoints reachable without a session; everything else under /api/ requires one. The other paths are
# the frontend's page and files, the same for everyone: the frontend asks /api/v1/session who is signed in
PUBLIC_ENDPOINTS = {
    "healthz",
    "api_session.get_session",
    "api_session.login",
    "api_session.logout",
}


def require_login():
    """before_request hook: deny by default instead of relying on per-route decorators."""
    if not request.path.startswith("/api/") or request.endpoint in PUBLIC_ENDPOINTS or "user_id" in session:
        return None
    return jsonify({"error": "Sign in first."}), 401

