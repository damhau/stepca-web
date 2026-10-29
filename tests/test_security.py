import re

import pytest

from app import create_app
from tests.conftest import PASSWORD, ApiClient

# Reachable without signing in: the sign-in API and the container health check. Paths outside /api/ are
# the frontend's page and files, the same for everyone
PUBLIC_ENDPOINTS = {"healthz", "api_session.get_session", "api_session.login", "api_session.logout"}
WRITES = {"POST", "PUT", "PATCH", "DELETE"}


def api_routes(app, methods):
    """Every registered (endpoint, method, path) of the API, with URL parameters filled in."""
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/"):
            continue
        path = re.sub(r"<(?:[^:>]+:)?[^>]+>", "1", rule.rule)
        for method in sorted(rule.methods & methods):
            yield rule.endpoint, method, path


def test_every_api_route_requires_a_session(app):
    # With CSRF on, a signed-out write is already stopped by the CSRF check: test the session check alone
    app.config["WTF_CSRF_ENABLED"] = False
    client = app.test_client()
    checked = 0
    for endpoint, method, path in api_routes(app, {"GET"} | WRITES):
        if endpoint in PUBLIC_ENDPOINTS:
            continue
        response = client.open(path, method=method, json={})
        assert response.status_code == 401, (method, path)
        assert response.get_json() == {"error": "Sign in first."}
        checked += 1
    assert checked > 30


def test_every_write_requires_the_csrf_token(app, api):
    writes = list(api_routes(app, WRITES))
    assert len(writes) >= 12
    for endpoint, method, path in writes:
        response = api.client.open(path, method=method, json={"username": "admin", "password": PASSWORD})
        assert response.status_code == 400, (endpoint, method, path)
        assert "CSRF token" in response.get_json()["error"]


def test_a_token_from_another_session_is_refused(app, api):
    other = ApiClient(app)
    response = api.client.post("/api/v1/csr/preview", json={"csr_pem": "x"}, headers={"X-CSRFToken": other.token})
    assert response.status_code == 400


def test_signing_in_needs_the_csrf_token(app):
    response = app.test_client().post("/api/v1/session", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 400


def test_the_frontend_is_public_and_the_api_is_not(app):
    client = app.test_client()
    page = client.get("/certificates/123")
    assert page.status_code == 200 and '<div id="root">' in page.get_data(as_text=True)
    assert client.get("/assets/index-abc123.js").status_code == 200
    assert client.get("/api/v1/certificates").status_code == 401
    assert client.get("/api/v1/no-such-route").status_code == 401


def test_unknown_api_paths_are_404_not_the_frontend(api):
    response = api.get("/api/v1/no-such-route")
    assert response.status_code == 404 and response.get_json() == {"error": "Not found."}


def test_page_nonce_matches_the_content_security_policy(app):
    response = app.test_client().get("/")
    nonce = re.search(r'name="csp-nonce" content="([^"]+)"', response.get_data(as_text=True)).group(1)
    assert nonce != "__CSP_NONCE__"
    csp = dict(directive.strip().split(" ", 1) for directive in response.headers["Content-Security-Policy"].split(";"))
    assert csp["style-src"] == f"'self' 'nonce-{nonce}'"
    # Another response, another nonce
    assert nonce not in app.test_client().get("/").get_data(as_text=True)


def test_security_headers(app):
    headers = app.test_client().get("/").headers
    csp = dict(directive.strip().split(" ", 1) for directive in headers["Content-Security-Policy"].split(";"))
    assert csp["script-src"] == "'self'"
    assert csp["frame-ancestors"] == "'none'"
    assert csp["connect-src"] == "'self'"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "same-origin"
    # Plain HTTP and SESSION_COOKIE_SECURE off: no HSTS
    assert "Strict-Transport-Security" not in headers


@pytest.mark.parametrize(
    "old, new",
    [
        ("/x509/cert/42", "/certificates/42"),
        ("/x509/active", "/certificates?status=valid"),
        ("/acme/order/abc", "/acme/orders/abc"),
        ("/step/provisioners", "/provisioners"),
        ("/system/config", "/settings"),
        ("/auth/login", "/login"),
    ],
)
def test_old_bookmarks_still_work(app, old, new):
    response = app.test_client().get(old)
    assert response.status_code == 301 and response.headers["Location"] == new


def test_without_a_build_the_page_says_how_to_make_one(app, tmp_path):
    app.config["FRONTEND_DIR"] = str(tmp_path / "missing")
    response = app.test_client().get("/")
    assert response.status_code == 503 and "npm run build" in response.get_data(as_text=True)


def failed_login(client, token, address="203.0.113.7", headers=None):
    return client.post(
        "/api/v1/session",
        json={"username": "admin", "password": "wrong"},
        headers={"X-CSRFToken": token, **(headers or {})},
        environ_base={"REMOTE_ADDR": address},
    )


def test_failed_sign_ins_are_limited_per_address(app):
    app.config["LOGIN_RATE_LIMIT"] = "3 per minute"
    api = ApiClient(app)
    assert [failed_login(api.client, api.token).status_code for _ in range(4)] == [401, 401, 401, 429]
    blocked = failed_login(api.client, api.token)
    assert blocked.get_json() == {"error": "Too many attempts: try again later."}
    # Another address is not affected
    assert failed_login(api.client, api.token, address="203.0.113.8").status_code == 401


def test_successful_sign_ins_are_not_counted(app):
    app.config["LOGIN_RATE_LIMIT"] = "2 per minute"
    for _ in range(4):
        ApiClient(app, "admin")


def app_with(app, **overrides):
    """Another app with the test settings plus overrides (lower case, as in app.settings), for settings
    read once at startup."""
    return create_app(app.extensions["settings"].model_copy(update=overrides))


def test_client_address_comes_from_trusted_proxies(app):
    """Behind a proxy every client has the proxy's address: with TRUSTED_PROXIES, X-Forwarded-For is used."""
    proxied = app_with(app, trusted_proxies=1, login_rate_limit="1 per minute")
    api = ApiClient(proxied)

    def attempt(client_address):
        return failed_login(api.client, api.token, address="10.0.0.1", headers={"X-Forwarded-For": client_address}).status_code

    assert [attempt("198.51.100.1"), attempt("198.51.100.1"), attempt("198.51.100.2")] == [401, 429, 401]


def test_forwarded_for_is_ignored_without_trusted_proxies(app):
    """Otherwise anyone could pick a new address for each attempt."""
    app.config["LOGIN_RATE_LIMIT"] = "1 per minute"
    api = ApiClient(app)
    statuses = [failed_login(api.client, api.token, headers={"X-Forwarded-For": address}).status_code for address in ("198.51.100.1", "198.51.100.2")]
    assert statuses == [401, 429]


def test_https_deployment_gets_hsts_and_secure_cookies(app):
    client = app_with(app, session_cookie_secure=True).test_client()
    base = "https://stepca-web.test"
    token = client.get("/api/v1/session", base_url=base).get_json()["csrf_token"]
    # Over HTTPS, Flask-WTF also wants a same-origin Referer, which browsers send (Referrer-Policy: same-origin)
    response = client.post(
        "/api/v1/session",
        json={"username": "admin", "password": PASSWORD},
        base_url=base,
        headers={"X-CSRFToken": token, "Referer": f"{base}/login"},
    )
    assert response.status_code == 200
    assert "Secure" in response.headers["Set-Cookie"]
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")
