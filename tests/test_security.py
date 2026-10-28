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
