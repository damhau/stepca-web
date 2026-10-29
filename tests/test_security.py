import re

import pytest

from tests.conftest import PASSWORD, csrf_token

PUBLIC_ENDPOINTS = {"auth.login", "auth.logout", "static"}


def concrete_routes(app, methods):
    """Every registered (method, path) pair, with URL parameters filled in."""
    for rule in app.url_map.iter_rules():
        path = re.sub(r"<(?:[^:>]+:)?[^>]+>", "1", rule.rule)
        for method in sorted(rule.methods & methods):
            yield rule.endpoint, method, path


def test_every_route_requires_login(app):
    # With CSRF on, a logged-out POST is already stopped by the CSRF check: test the login check alone
    app.config["WTF_CSRF_ENABLED"] = False
    client = app.test_client()
    checked = 0
    for endpoint, method, path in concrete_routes(app, {"GET", "POST"}):
        if endpoint in PUBLIC_ENDPOINTS:
            continue
        response = client.open(path, method=method)
        if path.startswith("/api/"):
            assert response.status_code == 401, (method, path)
        else:
            assert response.status_code == 302, (method, path)
            assert response.headers["Location"].endswith("/auth/login"), (method, path)
        checked += 1
    assert checked > 25


def test_every_post_requires_csrf_token(app, client):
    posts = list(concrete_routes(app, {"POST"}))
    assert len(posts) >= 8
    for endpoint, _method, path in posts:
        response = client.post(path, data={"username": "admin", "password": PASSWORD, "cert_id": "1"})
        assert response.status_code == 400, (endpoint, path)
        assert b"CSRF" in response.data


def test_login_without_csrf_token_is_rejected(app):
    response = app.test_client().post("/auth/login", data={"username": "admin", "password": PASSWORD})
    assert response.status_code == 400


@pytest.mark.parametrize("path", ["/step/provisioner/Admin%20JWK/delete", "/step/admin/adm-1/delete"])
def test_deletes_reject_get(client, ca_client, path):
    assert client.get(path).status_code == 405
    ca_client.delete_provisioner.assert_not_called()
    ca_client.delete_admin.assert_not_called()


def test_deletes_work_with_post_and_token(client, ca_client):
    token = csrf_token(client)
    client.post("/step/provisioner/Admin%20JWK/delete", data={"csrf_token": token})
    ca_client.delete_provisioner.assert_called_once_with("Admin JWK")
    client.post("/step/admin/adm-1/delete", data={"csrf_token": token})
    ca_client.delete_admin.assert_called_once_with("adm-1")


def test_session_cookie_flags(app):
    client = app.test_client()
    token = csrf_token(client)
    response = client.post("/auth/login", data={"username": "admin", "password": PASSWORD, "csrf_token": token})
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_wrong_password_is_rejected(app):
    client = app.test_client()
    response = client.post("/auth/login", data={"username": "admin", "password": "nope", "csrf_token": csrf_token(client)})
    assert response.status_code == 200
    assert b"Invalid credentials" in response.data
    assert client.get("/").status_code == 302


def failed_login(client, token, address="203.0.113.7"):
    return client.post(
        "/auth/login", data={"username": "admin", "password": "wrong", "csrf_token": token}, environ_base={"REMOTE_ADDR": address}
    )


def test_failed_sign_ins_are_rate_limited(app):
    app.config["LOGIN_RATE_LIMIT"] = "3 per minute"
    client = app.test_client()
    token = csrf_token(client)
    assert [failed_login(client, token).status_code for _ in range(4)] == [200, 200, 200, 429]
    blocked = failed_login(client, token)
    assert blocked.status_code == 429
    assert "Too many failed sign-ins" in blocked.get_data(as_text=True)
    # Another address is not affected
    assert failed_login(client, token, address="203.0.113.8").status_code == 200


def test_successful_sign_ins_are_not_counted(app):
    app.config["LOGIN_RATE_LIMIT"] = "2 per minute"
    for _ in range(4):
        client = app.test_client()
        response = client.post("/auth/login", data={"username": "admin", "password": PASSWORD, "csrf_token": csrf_token(client)})
        assert response.status_code == 302


def app_with(app, **overrides):
    """Another app with the test settings plus overrides, for settings read once at startup."""
    from app import create_app
    from config import Config

    settings = {key: value for key, value in app.config.items() if key.isupper()}
    return create_app(type("Overridden", (Config,), {**settings, **overrides}))


def test_client_address_comes_from_trusted_proxies(app):
    """Behind a proxy every client has the proxy's address: with TRUSTED_PROXIES, X-Forwarded-For is used."""
    client = app_with(app, TRUSTED_PROXIES=1, LOGIN_RATE_LIMIT="1 per minute").test_client()
    token = csrf_token(client)

    def attempt(client_address):
        return client.post(
            "/auth/login",
            data={"username": "admin", "password": "wrong", "csrf_token": token},
            headers={"X-Forwarded-For": client_address},
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        ).status_code

    assert [attempt("198.51.100.1"), attempt("198.51.100.1"), attempt("198.51.100.2")] == [200, 429, 200]


def test_forwarded_for_is_ignored_without_trusted_proxies(app):
    """Otherwise anyone could pick a new address for each attempt."""
    app.config["LOGIN_RATE_LIMIT"] = "1 per minute"
    client = app.test_client()
    token = csrf_token(client)
    statuses = [
        client.post(
            "/auth/login", data={"username": "admin", "password": "wrong", "csrf_token": token}, headers={"X-Forwarded-For": address}
        ).status_code
        for address in ("198.51.100.1", "198.51.100.2")
    ]
    assert statuses == [200, 429]


def test_security_headers(client):
    headers = client.get("/").headers
    csp = dict(directive.strip().split(" ", 1) for directive in headers["Content-Security-Policy"].split(";"))
    assert csp["script-src"] == "'self'"
    assert csp["frame-ancestors"] == "'none'"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "same-origin"
    # Plain HTTP and SESSION_COOKIE_SECURE off: no HSTS
    assert "Strict-Transport-Security" not in headers


def test_https_deployment_gets_hsts_and_secure_cookies(app):
    client = app_with(app, SESSION_COOKIE_SECURE=True).test_client()
    html = client.get("/auth/login", base_url="https://stepca-web.test").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    # Over HTTPS, Flask-WTF also wants a same-origin Referer, which browsers send (Referrer-Policy: same-origin)
    response = client.post(
        "/auth/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": token},
        base_url="https://stepca-web.test",
        headers={"Referer": "https://stepca-web.test/auth/login"},
    )
    assert "Secure" in response.headers["Set-Cookie"]
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")
