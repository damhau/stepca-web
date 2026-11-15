"""Single sign-on with OpenID Connect, against a fake identity provider: no network, a key made for the test."""

import base64
import hashlib
import hmac
import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import g
from werkzeug.security import generate_password_hash

from app import create_app
from app.extensions import db
from app.libs.auth import oidc as oidc_module
from app.libs.auth.oidc import OIDCClient, OIDCError
from app.models.audit import AuditEvent
from app.settings import Settings
from tests.conftest import ApiClient, make_settings

ISSUER = "https://idp.test"
CLIENT_ID = "stepca-web"
CALLBACK = "https://pki.test/api/v1/session/oidc/callback"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeResponse:
    def __init__(self, status_code=200, body=None, text=None):
        self.status_code = status_code
        self._body = body
        self.text = text if text is not None else str(body)

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


class FakeJWKS:
    def get_signing_key_from_jwt(self, token):
        return type("SigningKey", (), {"key": RSA_KEY.public_key()})()


class FakeIdP:
    """The provider's discovery document, token endpoint and userinfo endpoint, and the ID tokens it signs."""

    def __init__(self):
        self.nonce = None
        self.claims = {}
        self.userinfo = {}
        self.discovery_issuer = ISSUER
        self.token_response = None
        self.auth_methods = ["client_secret_basic"]
        self.posts = []

    def discovery(self):
        return {
            "issuer": self.discovery_issuer,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/keys",
            "userinfo_endpoint": f"{ISSUER}/userinfo",
            "token_endpoint_auth_methods_supported": self.auth_methods,
        }

    def id_token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "user-1",
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce,
            "preferred_username": "alice",
            "groups": ["pki-admins"],
            **self.claims,
            **overrides,
        }
        claims = {key: value for key, value in claims.items() if value is not None}
        return jwt.encode(claims, RSA_KEY, algorithm="RS256", headers={"kid": "test-key"})

    def get(self, url, **kwargs):
        if url.endswith("/.well-known/openid-configuration"):
            return FakeResponse(200, self.discovery())
        if url.endswith("/userinfo"):
            return FakeResponse(200, self.userinfo)
        return FakeResponse(404, text="not found")

    def post(self, url, data=None, auth=None, **kwargs):
        self.posts.append({"url": url, "data": data, "auth": auth})
        if self.token_response is not None:
            return self.token_response
        return FakeResponse(200, {"id_token": self.id_token(), "access_token": "access", "token_type": "Bearer"})


@pytest.fixture
def idp(monkeypatch):
    provider = FakeIdP()
    monkeypatch.setattr(oidc_module.requests, "get", provider.get)
    monkeypatch.setattr(oidc_module.requests, "post", provider.post)
    monkeypatch.setattr(oidc_module.jwt, "PyJWKClient", lambda *args, **kwargs: FakeJWKS())
    return provider


CONFIG = {"OIDC_ISSUER": ISSUER, "OIDC_CLIENT_ID": CLIENT_ID, "OIDC_CLIENT_SECRET": "s3cret"}


def query_of(url):
    return {key: values[0] for key, values in parse_qs(urlparse(url).query).items()}


def start_and_finish(client, idp, params=None, **state):
    """The two halves of a sign-in, with what the provider would send in between."""
    url, pending = client.start(CALLBACK)
    idp.nonce = query_of(url)["nonce"]
    answer = {"code": "the-code", "state": pending["state"], **(params or {})}
    return client.finish(answer, {**pending, **state}, CALLBACK)


# --- The client ---------------------------------------------------------------------------------------


class TestStart:
    def test_asks_for_a_code_with_pkce_state_and_nonce(self, idp):
        url, pending = OIDCClient(CONFIG).start(CALLBACK)
        query = query_of(url)
        assert url.startswith(f"{ISSUER}/authorize?")
        assert query["response_type"] == "code" and query["client_id"] == CLIENT_ID and query["redirect_uri"] == CALLBACK
        assert query["scope"] == "openid profile email"
        assert query["code_challenge_method"] == "S256"
        assert query["code_challenge"] == oidc_module._pkce_challenge(pending["verifier"])
        assert query["state"] == pending["state"] and query["nonce"] == pending["nonce"]

    def test_every_attempt_has_its_own_secrets(self, idp):
        client = OIDCClient(CONFIG)
        first, second = client.start(CALLBACK)[1], client.start(CALLBACK)[1]
        assert all(first[key] != second[key] for key in first)

    def test_discovery_is_read_once(self, idp, monkeypatch):
        calls = []
        monkeypatch.setattr(oidc_module.requests, "get", lambda url, **kw: calls.append(url) or idp.get(url, **kw))
        client = OIDCClient(CONFIG)
        client.start(CALLBACK)
        client.start(CALLBACK)
        assert len(calls) == 1

    def test_discovery_of_another_issuer_is_refused(self, idp):
        idp.discovery_issuer = "https://evil.test"
        with pytest.raises(OIDCError, match="evil.test"):
            OIDCClient(CONFIG).start(CALLBACK)

    def test_unreachable_provider(self, idp, monkeypatch):
        def down(*args, **kwargs):
            raise requests.ConnectionError("no route")

        monkeypatch.setattr(oidc_module.requests, "get", down)
        with pytest.raises(OIDCError, match="discovery"):
            OIDCClient(CONFIG).start(CALLBACK)


class TestFinish:
    def test_returns_the_user_and_their_groups(self, idp):
        user = start_and_finish(OIDCClient(CONFIG), idp)
        assert user["id"] == "alice" and user["groups"] == ["pki-admins"]
        assert user["attributes"]["sub"] == "user-1"

    def test_the_code_is_swapped_with_the_verifier_and_the_secret(self, idp):
        client = OIDCClient(CONFIG)
        url, pending = client.start(CALLBACK)
        idp.nonce = query_of(url)["nonce"]
        client.finish({"code": "abc", "state": pending["state"]}, pending, CALLBACK)
        (post,) = idp.posts
        assert post["url"] == f"{ISSUER}/token"
        assert post["data"]["code"] == "abc" and post["data"]["code_verifier"] == pending["verifier"]
        assert post["data"]["redirect_uri"] == CALLBACK and post["data"]["grant_type"] == "authorization_code"
        assert post["auth"].password == "s3cret" and "client_secret" not in post["data"]

    def test_secret_in_the_body_when_the_provider_does_not_do_basic(self, idp):
        idp.auth_methods = ["client_secret_post"]
        start_and_finish(OIDCClient(CONFIG), idp)
        assert idp.posts[0]["data"]["client_secret"] == "s3cret" and idp.posts[0]["auth"] is None

    def test_a_string_group_claim_is_one_group(self, idp):
        idp.claims = {"groups": "pki-admins"}
        assert start_and_finish(OIDCClient(CONFIG), idp)["groups"] == ["pki-admins"]

    def test_the_username_and_groups_claims_are_configurable(self, idp):
        idp.claims = {"email": "alice@corp.test", "roles": ["ops"]}
        client = OIDCClient({**CONFIG, "OIDC_USERNAME_CLAIM": "email", "OIDC_GROUPS_CLAIM": "roles"})
        user = start_and_finish(client, idp)
        assert user["id"] == "alice@corp.test" and user["groups"] == ["ops"]

    @pytest.mark.parametrize("claim", [None, "", "  ", 42])
    def test_a_token_without_a_usable_username_is_refused(self, idp, claim):
        # None leaves the claim out of the token altogether
        idp.claims = {"preferred_username": claim}
        with pytest.raises(OIDCError, match="preferred_username"):
            start_and_finish(OIDCClient(CONFIG), idp)

    def test_required_group_ignores_case(self, idp):
        assert start_and_finish(OIDCClient({**CONFIG, "OIDC_REQUIRED_GROUP": "PKI-Admins"}), idp)
        with pytest.raises(OIDCError, match="required group"):
            start_and_finish(OIDCClient({**CONFIG, "OIDC_REQUIRED_GROUP": "other"}), idp)

    def test_groups_missing_from_the_token_come_from_userinfo(self, idp):
        idp.claims = {"groups": None}
        idp.userinfo = {"sub": "user-1", "groups": ["from-userinfo"]}
        assert start_and_finish(OIDCClient(CONFIG), idp)["groups"] == ["from-userinfo"]

    def test_userinfo_of_another_subject_is_ignored(self, idp):
        idp.claims = {"groups": None}
        idp.userinfo = {"sub": "someone-else", "groups": ["pki-admins"]}
        assert start_and_finish(OIDCClient(CONFIG), idp)["groups"] == []


class TestFinishRefusals:
    """Every one of these is an attack, or a provider misconfigured enough to look like one."""

    def test_state_that_is_not_ours(self, idp):
        with pytest.raises(OIDCError, match="state"):
            start_and_finish(OIDCClient(CONFIG), idp, params={"state": "forged"})

    def test_answer_without_a_sign_in_started_here(self, idp):
        with pytest.raises(OIDCError, match="started"):
            OIDCClient(CONFIG).finish({"code": "c", "state": "s"}, None, CALLBACK)

    def test_answer_without_a_code(self, idp):
        client = OIDCClient(CONFIG)
        _, pending = client.start(CALLBACK)
        with pytest.raises(OIDCError, match="no code"):
            client.finish({"state": pending["state"]}, pending, CALLBACK)

    def test_provider_error(self, idp):
        with pytest.raises(OIDCError, match="access_denied"):
            OIDCClient(CONFIG).finish({"error": "access_denied"}, None, CALLBACK)

    def test_nonce_of_another_sign_in(self, idp):
        client = OIDCClient(CONFIG)
        _, pending = client.start(CALLBACK)
        idp.nonce = "replayed"
        with pytest.raises(OIDCError, match="nonce"):
            client.finish({"code": "c", "state": pending["state"]}, pending, CALLBACK)

    def test_token_without_a_nonce(self, idp):
        client = OIDCClient(CONFIG)
        url, pending = client.start(CALLBACK)
        idp.nonce = None
        with pytest.raises(OIDCError, match="nonce"):
            client.finish({"code": "c", "state": pending["state"]}, pending, CALLBACK)

    @pytest.mark.parametrize(
        "claims, message",
        [
            ({"aud": "another-client"}, "not valid"),
            ({"iss": "https://evil.test"}, "not valid"),
            ({"exp": 1}, "not valid"),
            ({"aud": [CLIENT_ID, "other"]}, "azp"),
        ],
    )
    def test_token_that_is_not_for_us(self, idp, claims, message):
        idp.claims = claims
        with pytest.raises(OIDCError, match=message):
            start_and_finish(OIDCClient(CONFIG), idp)

    def test_several_audiences_are_fine_when_issued_to_us(self, idp):
        idp.claims = {"aud": [CLIENT_ID, "other"], "azp": CLIENT_ID}
        assert start_and_finish(OIDCClient(CONFIG), idp)["id"] == "alice"

    @pytest.mark.parametrize("missing", ["exp", "iat", "sub"])
    def test_token_without_a_required_claim(self, idp, missing, monkeypatch):
        client = OIDCClient(CONFIG)
        url, pending = client.start(CALLBACK)
        idp.nonce = query_of(url)["nonce"]
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u", "iat": now, "exp": now + 60, "nonce": idp.nonce, "preferred_username": "a"}
        del claims[missing]
        idp.token_response = FakeResponse(200, {"id_token": jwt.encode(claims, RSA_KEY, algorithm="RS256")})
        with pytest.raises(OIDCError, match="not valid"):
            client.finish({"code": "c", "state": pending["state"]}, pending, CALLBACK)

    def test_token_signed_by_another_key(self, idp):
        client = OIDCClient(CONFIG)
        url, pending = client.start(CALLBACK)
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u", "iat": now, "exp": now + 60, "nonce": query_of(url)["nonce"], "preferred_username": "mallory"}
        forged = jwt.encode(claims, rsa.generate_private_key(public_exponent=65537, key_size=2048), algorithm="RS256")
        idp.token_response = FakeResponse(200, {"id_token": forged})
        with pytest.raises(OIDCError, match="not valid"):
            client.finish({"code": "c", "state": pending["state"]}, pending, CALLBACK)

    def test_token_signed_with_the_public_key_as_a_shared_secret(self, idp):
        """The classic algorithm confusion: HS256 with the provider's public key as the HMAC secret."""
        client = OIDCClient(CONFIG)
        url, pending = client.start(CALLBACK)
        public_pem = RSA_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u", "iat": now, "exp": now + 60, "nonce": query_of(url)["nonce"], "preferred_username": "mallory"}
        header = {"alg": "HS256", "typ": "JWT"}
        def b64(data):
            return base64.urlsafe_b64encode(data).rstrip(b"=")

        signing_input = b64(json.dumps(header).encode()) + b"." + b64(json.dumps(claims).encode())
        signature = b64(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
        idp.token_response = FakeResponse(200, {"id_token": (signing_input + b"." + signature).decode()})
        with pytest.raises(OIDCError, match="HS256"):
            client.finish({"code": "c", "state": pending["state"]}, pending, CALLBACK)

    def test_unsigned_token(self, idp):
        client = OIDCClient(CONFIG)
        url, pending = client.start(CALLBACK)
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u", "iat": now, "exp": now + 60, "nonce": query_of(url)["nonce"], "preferred_username": "mallory"}
        idp.token_response = FakeResponse(200, {"id_token": jwt.encode(claims, None, algorithm="none")})
        with pytest.raises(OIDCError, match="none"):
            client.finish({"code": "c", "state": pending["state"]}, pending, CALLBACK)

    @pytest.mark.parametrize(
        "response, message",
        [
            (FakeResponse(400, text='{"error":"invalid_grant"}'), "invalid_grant"),
            (FakeResponse(200, body=None, text="<html>"), "JSON"),
            (FakeResponse(200, {"access_token": "only"}), "no id_token"),
        ],
    )
    def test_token_endpoint_failures(self, idp, response, message):
        idp.token_response = response
        with pytest.raises(OIDCError, match=message):
            start_and_finish(OIDCClient(CONFIG), idp)

    def test_token_endpoint_unreachable(self, idp, monkeypatch):
        def down(*args, **kwargs):
            raise requests.Timeout("slow")

        monkeypatch.setattr(oidc_module.requests, "post", down)
        with pytest.raises(OIDCError, match="token endpoint"):
            start_and_finish(OIDCClient(CONFIG), idp)


# --- The routes ---------------------------------------------------------------------------------------


@pytest.fixture
def make_app(tmp_path):
    """An app with single sign-on; `groups` become roles through ROLE_*_GROUP."""

    def make(**overrides):
        values = {
            "oidc_enabled": True,
            "oidc_issuer": ISSUER,
            "oidc_client_id": CLIENT_ID,
            "oidc_client_secret": "s3cret",
            "oidc_redirect_uri": CALLBACK,
            "role_admin_group": "pki-admins",
            "role_operator_group": "pki-operators",
            "default_role": "none",
        }
        app = create_app(make_settings(tmp_path, **{**values, **overrides}))

        # As in conftest.app: the app context stays pushed for the whole test, so Flask-WTF's per-request
        # token cache would outlive the session that a sign-in replaces
        @app.before_request
        def fresh_csrf_cache():
            g.pop("csrf_token", None)

        context = app.app_context()
        context.push()
        db.create_all()
        return app

    return make


def begin(api, next=None):
    """GET /session/oidc/login: the redirect to the provider, and its state and nonce."""
    response = api.get("/api/v1/session/oidc/login" + (f"?next={next}" if next else ""))
    assert response.status_code == 302, response.get_data(as_text=True)
    return response, query_of(response.headers["Location"])


def sign_in(api, idp, next=None, **claims):
    """The whole round trip, as the browser makes it: login, the provider, callback."""
    _, query = begin(api, next)
    idp.nonce = query["nonce"]
    idp.claims = claims
    return api.get(f"/api/v1/session/oidc/callback?code=the-code&state={query['state']}")


def last_audit():
    return db.session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()


class TestRoutes:
    def test_login_sends_the_browser_to_the_provider(self, make_app, idp):
        response, query = begin(ApiClient(make_app()))
        assert response.headers["Location"].startswith(f"{ISSUER}/authorize?")
        assert query["redirect_uri"] == CALLBACK and query["code_challenge_method"] == "S256"
        assert response.headers["Cache-Control"] == "no-store"

    def test_the_redirect_uri_defaults_to_this_apps_callback(self, make_app, idp):
        _, query = begin(ApiClient(make_app(oidc_redirect_uri=None)))
        assert query["redirect_uri"] == "http://localhost/api/v1/session/oidc/callback"

    def test_a_sign_in_makes_a_session_with_the_role_of_the_group(self, make_app, idp):
        api = ApiClient(make_app())
        response = sign_in(api, idp, groups=["pki-operators"])
        assert response.status_code == 302 and response.headers["Location"] == "/"
        info = api.get("/api/v1/session").get_json()
        assert info["authenticated"] and info["user"] == "alice" and info["role"] == "operator"
        event = last_audit()
        assert (event.user, event.action, event.success, event.detail) == ("alice", "login", True, "sso")

    def test_the_highest_group_wins(self, make_app, idp):
        api = ApiClient(make_app())
        sign_in(api, idp, groups=["pki-operators", "PKI-Admins"])
        assert api.get("/api/v1/session").get_json()["role"] == "admin"

    def test_it_returns_to_the_page_asked_for(self, make_app, idp):
        response = sign_in(ApiClient(make_app()), idp, next="/certificates%3Ftab%3Dexpiring", groups=["pki-admins"])
        assert response.headers["Location"] == "/certificates?tab=expiring"

    @pytest.mark.parametrize("target", ["//evil.test", "https://evil.test", "/%5Cevil.test", "evil", "/a%0Ab"])
    def test_it_never_returns_to_another_site(self, make_app, idp, target):
        response = sign_in(ApiClient(make_app()), idp, next=target, groups=["pki-admins"])
        assert response.headers["Location"] == "/"

    def test_a_user_without_a_role_is_refused(self, make_app, idp):
        api = ApiClient(make_app())
        response = sign_in(api, idp, groups=["interns"])
        assert response.headers["Location"] == "/login?error=no_access"
        assert not api.get("/api/v1/session").get_json()["authenticated"]
        assert api.get("/api/v1/dashboard").status_code == 401
        event = last_audit()
        assert (event.user, event.action, event.success) == ("alice", "login", False)

    def test_default_role_applies_to_everyone_else(self, make_app, idp):
        api = ApiClient(make_app(default_role="viewer"))
        sign_in(api, idp, groups=[])
        assert api.get("/api/v1/session").get_json()["role"] == "viewer"

    def test_required_group(self, make_app, idp):
        api = ApiClient(make_app(oidc_required_group="staff", default_role="viewer"))
        assert sign_in(api, idp, groups=["pki-admins"]).headers["Location"] == "/login?error=sso_failed"
        assert sign_in(api, idp, groups=["staff"]).headers["Location"] == "/"

    def test_a_forged_state_signs_nobody_in(self, make_app, idp):
        api = ApiClient(make_app())
        begin(api)
        response = api.get("/api/v1/session/oidc/callback?code=the-code&state=forged")
        assert response.headers["Location"] == "/login?error=sso_failed"
        assert not api.get("/api/v1/session").get_json()["authenticated"]
        assert "state does not match" in last_audit().detail

    def test_a_callback_nobody_asked_for_signs_nobody_in(self, make_app, idp):
        api = ApiClient(make_app())
        response = api.get("/api/v1/session/oidc/callback?code=the-code&state=anything")
        assert response.headers["Location"] == "/login?error=sso_failed"

    def test_an_answer_can_be_used_once(self, make_app, idp):
        api = ApiClient(make_app())
        _, query = begin(api)
        idp.nonce = query["nonce"]
        idp.claims = {"groups": ["pki-admins"]}
        url = f"/api/v1/session/oidc/callback?code=the-code&state={query['state']}"
        assert api.get(url).headers["Location"] == "/"
        # Signing in started a new session, with a new CSRF token
        api.token = api.get("/api/v1/session").get_json()["csrf_token"]
        assert api.delete("/api/v1/session").status_code == 200
        assert api.get(url).headers["Location"] == "/login?error=sso_failed"
        assert not api.get("/api/v1/session").get_json()["authenticated"]

    def test_the_providers_error_is_not_shown_to_the_user(self, make_app, idp):
        api = ApiClient(make_app())
        begin(api)
        response = api.get("/api/v1/session/oidc/callback?error=access_denied&error_description=secret+detail")
        assert response.headers["Location"] == "/login?error=sso_failed"
        assert "access_denied" in last_audit().detail

    def test_signing_in_starts_a_fresh_session(self, make_app, idp):
        app = make_app()
        api = ApiClient(app)
        with api.client.session_transaction() as session:
            session["planted"] = "by an attacker"
        sign_in(api, idp, groups=["pki-admins"])
        with api.client.session_transaction() as session:
            assert session["user_id"] == "alice" and session.permanent
            assert "planted" not in session and "oidc" not in session and "oidc_next" not in session

    def test_an_unreachable_provider_is_not_a_crash(self, make_app, idp, monkeypatch):
        def down(*args, **kwargs):
            raise requests.ConnectionError("no route")

        monkeypatch.setattr(oidc_module.requests, "get", down)
        response = ApiClient(make_app()).get("/api/v1/session/oidc/login")
        assert response.status_code == 302 and response.headers["Location"] == "/login?error=sso_unavailable"

    def test_failed_sign_ins_are_rate_limited(self, make_app, idp):
        api = ApiClient(make_app(login_rate_limit="2 per minute"))
        for _ in range(2):
            assert api.get("/api/v1/session/oidc/callback?error=x").status_code == 302
        assert api.get("/api/v1/session/oidc/callback?error=x").status_code == 429

    def test_the_session_says_how_to_sign_in(self, make_app, idp):
        info = ApiClient(make_app(oidc_display_name="Corp SSO")).get("/api/v1/session").get_json()
        assert info["sso_label"] == "Corp SSO" and info["password_login"] is True


class TestModes:
    def test_without_sso_there_is_no_button_and_no_route(self, app):
        api = ApiClient(app)
        info = api.get("/api/v1/session").get_json()
        assert info["sso_label"] is None and info["password_login"] is True
        assert api.get("/api/v1/session/oidc/login").status_code == 404
        assert api.get("/api/v1/session/oidc/callback").status_code == 404

    def test_sso_only_turns_the_password_form_off(self, make_app, idp):
        api = ApiClient(make_app(auth_backend="oidc"))
        info = api.get("/api/v1/session").get_json()
        assert info["password_login"] is False and info["sso_label"] == "Single sign-on"
        response = api.post("/api/v1/session", json={"username": "admin", "password": "testpw"})
        assert response.status_code == 403

    def test_sso_beside_local_users_keeps_both(self, make_app, idp, tmp_path):
        (tmp_path / "local_users.json").write_text(json.dumps({"root": {"password_hash": generate_password_hash("pw"), "role": "admin"}}))
        api = ApiClient(make_app(auth_backend="local"))
        assert api.get("/api/v1/session").get_json()["password_login"] is True
        assert api.post("/api/v1/session", json={"username": "root", "password": "pw"}).status_code == 200
        api = ApiClient(make_app(auth_backend="local"))
        assert sign_in(api, idp, groups=["pki-admins"]).headers["Location"] == "/"


class TestSettings:
    def test_issuer_and_client_are_required(self, tmp_path):
        with pytest.raises(ValueError, match="OIDC_ISSUER.*OIDC_CLIENT_ID"):
            make_settings(tmp_path, oidc_enabled=True)

    def test_a_secret_is_required(self, tmp_path):
        with pytest.raises(ValueError, match="OIDC_CLIENT_SECRET"):
            make_settings(tmp_path, auth_backend="oidc", oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID)

    def test_the_secret_can_be_a_file(self, tmp_path):
        (tmp_path / "oidc_secret").write_text("from-a-file\n")
        settings = make_settings(
            tmp_path, oidc_enabled=True, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_client_secret_file="oidc_secret"
        )
        assert settings.flask_config()["OIDC_CLIENT_SECRET"] == "from-a-file"

    def test_a_missing_secret_file_is_named(self, tmp_path):
        with pytest.raises(ValueError, match="OIDC_CLIENT_SECRET_FILE"):
            make_settings(tmp_path, oidc_enabled=True, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_client_secret_file="nope")

    def test_nothing_is_required_when_it_is_off(self, tmp_path):
        settings = make_settings(tmp_path)
        assert not settings.oidc_active and settings.flask_config()["OIDC_CLIENT_SECRET"] is None

    def test_a_missing_ca_file_stops_the_app(self, tmp_path):
        with pytest.raises(RuntimeError, match="OIDC_CA_FILE"):
            create_app(make_settings(tmp_path, auth_backend="oidc", oidc_issuer=ISSUER, oidc_client_id="c", oidc_client_secret="s", oidc_ca_file="/nonexistent/ca.crt"))

    def test_the_configuration_page_never_shows_the_secret(self, make_app, idp, monkeypatch):
        app = make_app()
        ca = mock.MagicMock()
        ca.admin_key_source.return_value = "in memory"
        app.extensions["stepca"] = ca
        monkeypatch.setattr("app.services.provisioners.identity_type", lambda: "SUPER_ADMIN")
        api = ApiClient(app)
        sign_in(api, idp, groups=["pki-admins"])
        response = api.get("/api/v1/settings")
        assert response.status_code == 200
        assert "s3cret" not in response.get_data(as_text=True)
        values = {item["label"]: item["value"] for section in response.get_json()["sections"] for item in section["items"]}
        assert values["Single sign-on"] == "enabled (OpenID Connect)" and values["OIDC client secret"] == "set"

    def test_environment_variables_name_the_settings(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        for name, value in {
            "SECRET_KEY": "s", "CA_URL": "https://ca.test", "DATABASE_HOST": "db", "AUTH_BACKEND": "oidc",
            "OIDC_ISSUER": ISSUER, "OIDC_CLIENT_ID": "c", "OIDC_CLIENT_SECRET": "x", "OIDC_GROUPS_CLAIM": "roles",
        }.items():
            monkeypatch.setenv(name, value)
        settings = Settings()  # type: ignore[call-arg]
        assert settings.oidc_active and not settings.password_login and settings.oidc_groups_claim == "roles"
