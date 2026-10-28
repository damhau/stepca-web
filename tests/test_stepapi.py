"""StepCAClient against a mocked network: token claims, pagination and root pinning."""

import hashlib
import json
from unittest import mock

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwk as jwcrypto_jwk

from app.libs import stepapi
from app.libs.stepapi import CAToken, StepCAClient
from tests.conftest import make_cert

CA_URL = "https://ca.test:9000"


@pytest.fixture
def ca_client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    client = StepCAClient(CA_URL)
    monkeypatch.setattr(client, "_ca_root", lambda: "ca_root.crt")
    return client


def private_jwk():
    key = jwcrypto_jwk.JWK.generate(kty="EC", crv="P-256")
    data = json.loads(key.export_private())
    data["kid"] = key.thumbprint()
    return data


def response(status=200, body=None):
    return mock.Mock(status_code=status, ok=200 <= status < 300, json=lambda: body or {}, text=json.dumps(body or {}))


def test_ca_token_claims():
    token = CAToken(CA_URL, "/1.0/sign", "ab" * 32, "Admin JWK", "web.test", private_jwk(), sans=["web.test", "10.0.0.1"]).token
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["aud"] == f"{CA_URL}/1.0/sign"
    assert claims["iss"] == "Admin JWK"
    assert claims["sub"] == "web.test"
    assert claims["sans"] == ["web.test", "10.0.0.1"]
    assert claims["exp"] - claims["iat"] == 300


def test_revoke_token_subject_is_the_decimal_serial(ca_client, monkeypatch):
    """step-ca requires the token subject to equal the decimal serial (INT-1)."""
    monkeypatch.setattr(ca_client, "public_get_provisioner_by_name", lambda name: {"key": {}, "encryptedKey": ""})
    monkeypatch.setattr(ca_client, "decrypt_and_merge", lambda **kwargs: private_jwk())
    sent = {}

    def fake_request(method, path, json_payload=None, params=None):
        sent.update(path=path, payload=json_payload)
        return response(200, {"status": "ok"})

    monkeypatch.setattr(ca_client, "_request_noauth", fake_request)
    ca_client.revoke("0119960802063269571811733802872440608485", "pw")

    serial = "119960802063269571811733802872440608485"
    assert sent["path"] == "/1.0/revoke"
    assert sent["payload"]["serial"] == serial
    claims = jwt.decode(sent["payload"]["ott"], options={"verify_signature": False})
    assert claims["sub"] == serial
    assert claims["aud"] == f"{CA_URL}/1.0/revoke"


def test_revoke_raises_with_the_ca_error(ca_client, monkeypatch):
    monkeypatch.setattr(ca_client, "public_get_provisioner_by_name", lambda name: {"key": {}, "encryptedKey": ""})
    monkeypatch.setattr(ca_client, "decrypt_and_merge", lambda **kwargs: private_jwk())
    monkeypatch.setattr(ca_client, "_request_noauth", lambda *a, **k: response(400, {"message": "already revoked"}))
    with pytest.raises(RuntimeError, match="already revoked"):
        ca_client.revoke("42", "pw")


def test_admin_token_audience_excludes_the_query_string(ca_client, monkeypatch):
    """step-ca compares the audience with the request path only."""
    audiences = []
    monkeypatch.setattr(ca_client, "_get_jwt_token", lambda audience: audiences.append(audience) or "token")
    with mock.patch.object(stepapi.requests, "request", return_value=response()) as request:
        ca_client._request("GET", "/admin/provisioners", params={"limit": 100, "cursor": "abc"})
    assert audiences == [f"{CA_URL}/admin/provisioners"]
    args, kwargs = request.call_args
    assert args == ("GET", f"{CA_URL}/admin/provisioners")
    assert kwargs["params"] == {"limit": 100, "cursor": "abc"}
    assert kwargs["verify"] == "ca_root.crt"
    assert kwargs["timeout"] == stepapi.TIMEOUT


def test_lists_follow_the_cursor(ca_client, monkeypatch):
    pages = iter(
        [
            response(body={"provisioners": [{"name": f"p{i}"} for i in range(100)], "nextCursor": "c1"}),
            response(body={"provisioners": [{"name": "late-jwk"}], "nextCursor": ""}),
        ]
    )
    calls = []
    monkeypatch.setattr(ca_client, "_request", lambda method, path, params=None: calls.append(dict(params)) or next(pages))
    provisioners = ca_client.list_provisioners()["provisioners"]
    assert len(provisioners) == 101
    assert calls == [{"limit": 100}, {"limit": 100, "cursor": "c1"}]


def test_lists_stop_when_the_cursor_repeats(ca_client, monkeypatch):
    monkeypatch.setattr(ca_client, "_request", lambda *a, **k: response(body={"admins": [{"id": "a"}], "nextCursor": "same"}))
    assert len(ca_client.list_admins()["admins"]) == 2


def test_lists_return_none_on_error(ca_client, monkeypatch):
    monkeypatch.setattr(ca_client, "_request", lambda *a, **k: response(500))
    assert ca_client.list_provisioners() is None


def test_unknown_provisioner_raises(ca_client, monkeypatch):
    monkeypatch.setattr(ca_client, "_request_noauth", lambda *a, **k: response(body={"provisioners": [{"name": "other"}]}))
    with pytest.raises(ValueError, match="'Admin JWK' not found"):
        ca_client.public_get_provisioner_by_name("Admin JWK")


class TestRootPinning:
    @pytest.fixture
    def root(self):
        der = make_cert(1, "Test Root CA")
        pem = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode()
        return pem, hashlib.sha256(der).hexdigest()

    @pytest.fixture
    def client(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        return StepCAClient(CA_URL)

    def test_root_is_downloaded_once_and_pinned(self, client, root):
        pem, fingerprint = root
        client.ca_fingerprint = fingerprint
        with mock.patch.object(stepapi.requests, "get", return_value=response(body={"ca": pem})) as get:
            assert client._ca_root() == "ca_root.crt"
            assert client._ca_root() == "ca_root.crt"
        get.assert_called_once()
        assert get.call_args.args == (f"{CA_URL}/root/{fingerprint}",)
        assert open("ca_root.crt").read() == pem

    def test_root_with_another_fingerprint_is_refused(self, client, root):
        pem, _ = root
        client.ca_fingerprint = "11" * 32
        with mock.patch.object(stepapi.requests, "get", return_value=response(body={"ca": pem})):
            with pytest.raises(ConnectionError, match="fingerprints do not match"):
                client._ca_root()

    def test_stale_cached_root_is_replaced(self, client, root):
        pem, fingerprint = root
        stale = x509.load_der_x509_certificate(make_cert(2, "Other Root")).public_bytes(serialization.Encoding.PEM).decode()
        open("ca_root.crt", "w").write(stale)
        client.ca_fingerprint = fingerprint
        with mock.patch.object(stepapi.requests, "get", return_value=response(body={"ca": pem})):
            client._ca_root()
        assert open("ca_root.crt").read() == pem

    def test_missing_fingerprint_is_refused(self, client):
        client.ca_fingerprint = ""
        with pytest.raises(ConnectionError, match="CA_FINGERPRINT"):
            client._ca_root()
