"""Creating and editing provisioners."""

import re

import pytest
from werkzeug.datastructures import MultiDict

from app.libs.provisioners import duration_seconds, edit_provisioner
from app.libs.stepapi import StepCAClient

ACME = {
    "id": "prov-1",
    "authorityId": "00000000-0000-0000-0000-000000000000",
    "type": "ACME",
    "name": "acme",
    "details": {"ACME": {"challenges": ["HTTP_01", "DEVICE_ATTEST_01"]}},
    "claims": {"x509": {"enabled": True, "durations": {"default": "24h", "min": "5m", "max": "48h"}}},
    "createdAt": "2026-10-29T12:30:39Z",
    "deletedAt": "0001-01-01T00:00:00Z",
}


def form(**fields):
    return MultiDict([(key, value) for key, values in fields.items() for value in (values if isinstance(values, list) else [values])])


@pytest.mark.parametrize("value, seconds", [("24h", 86400), ("1h30m", 5400), ("90m", 5400), ("2.5h", 9000), ("300ms", 0.3)])
def test_go_durations(value, seconds):
    assert duration_seconds(value) == pytest.approx(seconds)


@pytest.mark.parametrize("value", ["24", "1d", "h", "24h ", "-1h"])
def test_invalid_durations(value):
    with pytest.raises(ValueError, match="not a duration"):
        duration_seconds(value)


def test_edit_changes_claims_and_acme_options():
    updated = edit_provisioner(
        ACME,
        form(x509_enabled="on", duration_default="12h", duration_max="72h", disable_renewal="on", force_cn="on", challenges=["DNS_01", "TLS_ALPN_01"]),
    )
    assert updated["claims"] == {
        "x509": {"enabled": True, "durations": {"default": "12h", "max": "72h"}},
        "disableRenewal": True,
        "allowRenewalAfterExpiry": False,
    }
    # device-attest-01 isn't in the form: it is kept
    assert updated["details"]["ACME"] == {"forceCn": True, "requireEab": False, "challenges": ["DNS_01", "TLS_ALPN_01", "DEVICE_ATTEST_01"]}
    # What step-ca refuses to change is left alone, and the original is untouched
    assert {key: updated[key] for key in ("id", "authorityId", "type", "name", "createdAt", "deletedAt")} == {
        key: ACME[key] for key in ("id", "authorityId", "type", "name", "createdAt", "deletedAt")
    }
    assert ACME["claims"]["x509"]["durations"]["default"] == "24h"


def test_empty_durations_fall_back_to_the_ca_defaults():
    assert "durations" not in edit_provisioner(ACME, form(x509_enabled="on"))["claims"]["x509"]


def test_invalid_duration_is_refused():
    with pytest.raises(ValueError, match="not a duration"):
        edit_provisioner(ACME, form(x509_enabled="on", duration_max="2 days"))


@pytest.mark.parametrize(
    "fields, error",
    [({}, "must keep issuing"), ({"x509_enabled": "on", "duration_max": "12h"}, "at least 24h")],
)
def test_the_app_provisioner_keeps_issuing_its_certificate(fields, error):
    with pytest.raises(ValueError, match=error):
        edit_provisioner(ACME, form(**fields), app_provisioner="acme")
    edit_provisioner(ACME, form(**fields), app_provisioner="another")


def test_provisioner_names_are_escaped_in_paths():
    assert StepCAClient._provisioner_path("Admin JWK") == "/admin/provisioners/Admin%20JWK"
    assert StepCAClient._provisioner_path("a/b") == "/admin/provisioners/a%2Fb"


def token(client):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get("/step/provisioners").get_data(as_text=True)).group(1)


def test_edit_page_shows_the_current_values(client, ca_client):
    ca_client.get_provisioner.return_value = ACME
    html = client.get("/step/provisioner/acme/edit").get_data(as_text=True)
    assert re.search(r'name="duration_max"[^>]*value="48h"', html)
    assert re.search(r'value="HTTP_01"[^>]*\s+checked', html)
    assert not re.search(r'value="DNS_01"[^>]*\s+checked', html)


def test_edit_sends_the_updated_provisioner(client, ca_client):
    ca_client.get_provisioner.return_value = ACME
    response = client.post(
        "/step/provisioner/acme/edit", data={"x509_enabled": "on", "duration_default": "1h", "challenges": "HTTP_01", "csrf_token": token(client)}
    )
    assert response.headers["Location"] == "/step/provisioners"
    name, sent = ca_client.update_provisioner.call_args.args
    assert name == "acme"
    assert sent["claims"]["x509"]["durations"] == {"default": "1h"}
    assert sent["details"]["ACME"]["challenges"] == ["HTTP_01", "DEVICE_ATTEST_01"]


def test_edit_shows_the_ca_error(client, ca_client):
    ca_client.get_provisioner.return_value = ACME
    ca_client.update_provisioner.side_effect = RuntimeError("default duration cannot be greater than the maximum")
    response = client.post("/step/provisioner/acme/edit", data={"x509_enabled": "on", "csrf_token": token(client)}, follow_redirects=True)
    assert "default duration cannot be greater than the maximum" in response.get_data(as_text=True)


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_only_admins_edit_provisioners(login_as, ca_client, role):
    ca_client.get_provisioner.return_value = ACME
    assert login_as(role).get("/step/provisioner/acme/edit").status_code == 403


def test_create_acme_provisioner(client, ca_client):
    client.post(
        "/step/provisioners",
        data={"name": "acme-new", "type": "ACME", "duration_default": "24h", "challenges": ["DNS_01", "BOGUS"], "require_eab": "on", "csrf_token": token(client)},
    )
    kwargs = ca_client.create_provisioner_acme.call_args.kwargs
    assert kwargs["details"] == {"ACME": {"requireEab": True, "forceCn": False, "challenges": ["DNS_01"]}}
    assert kwargs["claims"] == {"x509": {"enabled": True, "durations": {"default": "24h"}}}


def test_create_refuses_an_invalid_duration(client, ca_client):
    response = client.post(
        "/step/provisioners", data={"name": "jwk-new", "type": "JWK", "duration_max": "forever", "passphrase": "pw", "csrf_token": token(client)},
        follow_redirects=True,
    )
    assert "not a duration" in response.get_data(as_text=True)
    ca_client.create_provisioner_jwk.assert_not_called()
