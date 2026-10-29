"""Signing a CSR: the form, the preview, the token sent to step-ca and the errors shown."""

import ipaddress

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.libs.cert_utils import describe_csr
from app.stepca.client import SignError, StepCAClient
from tests.conftest import make_cert
from tests.test_ca_client import CA_URL, response


def make_csr(common_name="web.test", sans=("web.test",), ips=()):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else [])
    )
    names = [x509.DNSName(name) for name in sans] + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def jwk_provisioner(tmp_path, monkeypatch):
    """A StepCAClient whose public provisioner list holds one JWK provisioner, with password "right"."""
    monkeypatch.chdir(tmp_path)
    client = StepCAClient(CA_URL)
    monkeypatch.setattr(client, "_ca_root", lambda: "ca_root.crt")
    public, encrypted = client.generate_default_key_pair(b"right")
    monkeypatch.setattr(client, "public_get_provisioner_by_name", lambda name: {"name": name, "key": public, "encryptedKey": encrypted})
    sent = {}

    def fake_request(method, path, json_payload=None, params=None, expected=()):
        sent.update(path=path, payload=json_payload)
        crt = x509.load_der_x509_certificate(make_cert(77, "web.test")).public_bytes(serialization.Encoding.PEM).decode()
        return response(201, {"crt": crt})

    monkeypatch.setattr(client, "_request_noauth", fake_request)
    client.sent = sent
    return client


def test_preview_describes_the_csr():
    preview = describe_csr(make_csr(sans=("web.test", "www.web.test"), ips=("10.0.0.1",)))
    assert preview == {
        "subject": "CN=web.test",
        "common_name": "web.test",
        "sans": ["web.test", "www.web.test", "10.0.0.1"],
        "key": "EC secp256r1",
        "signature_valid": True,
    }


def test_token_carries_every_san_and_the_validity(jwk_provisioner):
    jwk_provisioner.sign(make_csr(sans=("web.test",), ips=("10.0.0.1",)), "dev", "right", not_after="72h")
    payload = jwk_provisioner.sent["payload"]
    assert payload["notAfter"] == "72h"
    claims = jwt.decode(payload["ott"], options={"verify_signature": False})
    # step-ca requires the token's SANs to be exactly the CSR's
    assert claims["sans"] == ["web.test", "10.0.0.1"]
    assert claims["sub"] == "web.test"


def test_csr_without_common_name_uses_its_first_san(jwk_provisioner):
    jwk_provisioner.sign(make_csr(common_name=None, sans=("only-san.test",)), "dev", "right")
    claims = jwt.decode(jwk_provisioner.sent["payload"]["ott"], options={"verify_signature": False})
    assert claims["sub"] == "only-san.test"
    assert "notAfter" not in jwk_provisioner.sent["payload"]


@pytest.mark.parametrize(
    "csr, password, message",
    [
        (make_csr(), "wrong", "Wrong password for provisioner 'dev'"),
        ("not a csr", "right", "not a PEM certificate signing request"),
        (make_csr(common_name=None, sans=()), "right", "neither a common name nor a subject alternative name"),
    ],
)
def test_readable_errors(jwk_provisioner, csr, password, message):
    with pytest.raises(SignError, match=message):
        jwk_provisioner.sign(csr, "dev", password)


def test_step_ca_refusal_is_explained(jwk_provisioner, monkeypatch):
    refusal = response(403, {"message": "requested duration of 900h is more than the authorized maximum certificate duration of 24h"})
    monkeypatch.setattr(jwk_provisioner, "_request_noauth", lambda *a, **k: refusal)
    with pytest.raises(SignError, match="step-ca refused: requested duration of 900h"):
        jwk_provisioner.sign(make_csr(), "dev", "right", not_after="900h")


def test_sign_errors_are_readable(api, ca_client):
    ca_client.sign.side_effect = SignError("Wrong password for provisioner 'Admin JWK'")
    response = api.post("/api/v1/certificates", json={"csr_pem": make_csr(), "provisioner": "Admin JWK", "password": "x"})
    assert response.get_json() == {"error": "The certificate was not signed: Wrong password for provisioner 'Admin JWK'."}
    assert "InvalidJWEData" not in response.get_data(as_text=True)


def test_sign_passes_the_csr_and_the_validity(api, ca_client):
    ca_client.sign.return_value = x509.load_der_x509_certificate(make_cert(88, "file.test"))
    csr = make_csr("file.test", sans=("file.test",))
    api.post("/api/v1/certificates", json={"csr_pem": csr, "provisioner": "Admin JWK", "password": "x", "valid_for": "48h"})
    args, kwargs = ca_client.sign.call_args
    assert args[0] == csr and kwargs["not_after"] == "48h"


def test_sign_refuses_an_invalid_validity(api, ca_client):
    response = api.post("/api/v1/certificates", json={"csr_pem": make_csr(), "provisioner": "Admin JWK", "password": "x", "valid_for": "two days"})
    assert response.status_code == 422 and "'two days' is not a duration" in response.get_json()[0]["msg"]
    ca_client.sign.assert_not_called()


def test_sign_refuses_a_huge_csr(api, ca_client):
    response = api.post("/api/v1/certificates", json={"csr_pem": "x" * (64 * 1024 + 1), "provisioner": "Admin JWK", "password": "x"})
    assert response.status_code == 422
    ca_client.sign.assert_not_called()


def test_viewers_cannot_preview(api_as):
    assert api_as("viewer").post("/api/v1/csr/preview", json={"csr_pem": make_csr()}).status_code == 403
