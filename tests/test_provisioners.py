"""Creating and editing provisioners."""

import pytest

from app.libs.provisioners import apply_changes, duration_seconds
from app.stepca.client import StepCAClient

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


def changes(durations=None, acme=None, **flags):
    """What the edit form sends (the API's ProvisionerUpdate)."""
    return {"durations": durations or {}, "acme": acme, **flags}


@pytest.mark.parametrize("value, seconds", [("24h", 86400), ("1h30m", 5400), ("90m", 5400), ("2.5h", 9000), ("300ms", 0.3)])
def test_go_durations(value, seconds):
    assert duration_seconds(value) == pytest.approx(seconds)


@pytest.mark.parametrize("value", ["24", "1d", "h", "24h ", "-1h"])
def test_invalid_durations(value):
    with pytest.raises(ValueError, match="not a duration"):
        duration_seconds(value)


def test_edit_changes_claims_and_acme_options():
    updated = apply_changes(
        ACME,
        changes(
            durations={"default": "12h", "max": "72h"},
            disable_renewal=True,
            acme={"force_cn": True, "require_eab": False, "challenges": ["DNS_01", "TLS_ALPN_01"]},
        ),
    )
    assert updated["claims"] == {
        # enabled is left as step-ca had it
        "x509": {"enabled": True, "durations": {"default": "12h", "max": "72h"}},
        "disableRenewal": True,
        "allowRenewalAfterExpiry": False,
    }
    # device-attest-01 isn't offered by the form: it is kept
    assert updated["details"]["ACME"] == {"forceCn": True, "requireEab": False, "challenges": ["DNS_01", "TLS_ALPN_01", "DEVICE_ATTEST_01"]}
    # What step-ca refuses to change is left alone, and the original is untouched
    assert {key: updated[key] for key in ("id", "authorityId", "type", "name", "createdAt", "deletedAt")} == {
        key: ACME[key] for key in ("id", "authorityId", "type", "name", "createdAt", "deletedAt")
    }
    assert ACME["claims"]["x509"]["durations"]["default"] == "24h"


def test_empty_durations_fall_back_to_the_ca_defaults():
    assert "durations" not in apply_changes(ACME, changes(durations={"default": None}))["claims"]["x509"]


def test_invalid_duration_is_refused():
    with pytest.raises(ValueError, match="not a duration"):
        apply_changes(ACME, changes(durations={"max": "2 days"}))


@pytest.mark.parametrize(
    "fields, error",
    [(changes(durations={"max": "12h"}), "at least 24h"), (changes(durations={"max": "1h30m"}), "at least 24h")],
)
def test_the_app_provisioner_keeps_issuing_its_certificate(fields, error):
    with pytest.raises(ValueError, match=error):
        apply_changes(ACME, fields, app_provisioner="acme")
    apply_changes(ACME, fields, app_provisioner="another")


def test_acme_options_are_left_alone_without_them():
    assert apply_changes(ACME, changes())["details"] == ACME["details"]


def test_provisioner_names_are_escaped_in_paths():
    assert StepCAClient._provisioner_path("Admin JWK") == "/admin/provisioners/Admin%20JWK"
    assert StepCAClient._provisioner_path("a/b") == "/admin/provisioners/a%2Fb"


def test_edit_shows_step_cas_refusal(api, ca_client):
    from app.stepca.client import CAError

    ca_client.get_provisioner.return_value = ACME
    ca_client.update_provisioner.side_effect = CAError("default duration cannot be greater than the maximum")
    response = api.put("/api/v1/provisioners/acme", json={})
    assert response.status_code == 422
    assert "default duration cannot be greater than the maximum" in response.get_json()["error"]


def test_create_refuses_unknown_challenges(api, ca_client):
    response = api.post("/api/v1/provisioners", json={"name": "acme-new", "type": "ACME", "acme": {"challenges": ["DNS_01", "BOGUS"]}})
    assert response.status_code == 422
    ca_client.create_provisioner_acme.assert_not_called()
