"""The frontend (frontend/, built into frontend/dist): its files, and its page for every path that isn't the API.

The page is the same for everyone; the frontend then asks /api/v1/session who is signed in. The page gets a
nonce for the style element its dialogs add, which the Content-Security-Policy allows only with it.
"""

from pathlib import Path

from flask import Blueprint, Response, abort, current_app, redirect, request, send_from_directory

bp = Blueprint("web", __name__)

# What the old pages became, so that bookmarks keep working
MOVED = {
    "/auth/login": "/login",
    "/x509/all": "/certificates",
    "/x509/active": "/certificates?status=valid",
    "/x509/expiring": "/certificates?status=expiring",
    "/x509/revoked": "/certificates?status=revoked",
    "/acme/certs": "/acme/certificates",
    "/acme/authzs": "/acme/authorizations",
    "/step/provisioners": "/provisioners",
    "/step/admins": "/admins",
    "/step/ca": "/ca",
    "/step/service": "/service",
    "/system/config": "/settings",
    "/system/audit": "/audit",
}
MOVED_PREFIXES = {"/x509/cert/": "/certificates/", "/acme/account/": "/acme/accounts/", "/acme/order/": "/acme/orders/"}

NONCE_PLACEHOLDER = "__CSP_NONCE__"


def dist() -> Path:
    return Path(current_app.config["FRONTEND_DIR"])


def page() -> Response:
    index = dist() / "index.html"
    if not index.is_file():
        return Response(f"The frontend is not built: run `npm run build` in frontend/ (looked in {dist()}).", 503, mimetype="text/plain")
    html = index.read_text().replace(NONCE_PLACEHOLDER, getattr(request, "csp_nonce", ""))
    response = Response(html, mimetype="text/html")
    # Always the current build's asset names
    response.headers["Cache-Control"] = "no-cache"
    return response


@bp.route("/assets/<path:filename>")
def assets(filename):
    # Named after their content: they never change
    return send_from_directory(dist() / "assets", filename, max_age=365 * 24 * 3600)


@bp.route("/<any('favicon.svg', 'theme.js'):filename>")
def public_file(filename):
    return send_from_directory(dist(), filename, max_age=3600)


@bp.route("/", defaults={"path": ""})
@bp.route("/<path:path>")
def spa(path):
    if path.startswith("api/"):
        abort(404)
    url = "/" + path
    if url in MOVED:
        return redirect(MOVED[url], 301)
    for old, new in MOVED_PREFIXES.items():
        if url.startswith(old):
            return redirect(new + url.removeprefix(old), 301)
    return page()
