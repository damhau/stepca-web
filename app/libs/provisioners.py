"""Editing step-ca provisioners: the form fields, applied to the record the Admin API returns."""

import copy
import re

# Go durations, as step-ca's claims take them: 24h, 90m, 1h30m, 2.5h
GO_DURATION = re.compile(r"^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$")
GO_DURATION_UNITS = {"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600}

# The ACME challenges the forms offer (linkedca.ACMEProvisioner_ChallengeType names)
ACME_CHALLENGES = [("HTTP_01", "http-01"), ("DNS_01", "dns-01"), ("TLS_ALPN_01", "tls-alpn-01")]

# The app asks its own provisioner for an admin certificate valid this long (StepCAClient.not_after)
APP_CERTIFICATE_HOURS = 24


def duration_seconds(value):
    if not GO_DURATION.match(value):
        raise ValueError(f"'{value}' is not a duration such as 24h, 90m or 1h30m")
    return sum(float(number) * GO_DURATION_UNITS[unit] for number, unit in re.findall(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)", value))


def durations_from_form(form):
    """{"default": ..., "min": ..., "max": ...} with the fields that are filled in."""
    durations = {}
    for field in ("default", "min", "max"):
        value = (form.get(f"duration_{field}") or "").strip()
        if value:
            duration_seconds(value)  # validates
            durations[field] = value
    return durations


def changes_from_form(form):
    """The edit form's fields as apply_changes() takes them."""
    return {
        "x509_enabled": "x509_enabled" in form,
        "durations": durations_from_form(form),
        "disable_renewal": "disable_renewal" in form,
        "allow_renewal_after_expiry": "allow_renewal_after_expiry" in form,
        "acme": {
            "force_cn": "force_cn" in form,
            "require_eab": "require_eab" in form,
            "challenges": form.getlist("challenges"),
        },
    }


def edit_provisioner(provisioner, form, app_provisioner=None):
    return apply_changes(provisioner, changes_from_form(form), app_provisioner)


def apply_changes(provisioner, changes, app_provisioner=None):
    """A copy of the provisioner (as GET /admin/provisioners/{name} returns it) with these changes:
    x509_enabled, durations ({"default", "min", "max"}, empty ones left out), disable_renewal,
    allow_renewal_after_expiry, and for an ACME provisioner acme ({"challenges", "force_cn", "require_eab"}).

    Only claims and ACME options change: step-ca refuses any change of id, type or dates.
    Raises ValueError on invalid input.
    """
    updated = copy.deepcopy(provisioner)
    claims = updated.setdefault("claims", {})
    x509 = claims.setdefault("x509", {})
    x509["enabled"] = bool(changes["x509_enabled"])
    durations = {field: value for field, value in (changes.get("durations") or {}).items() if value}
    for value in durations.values():
        duration_seconds(value)  # validates
    if durations:
        x509["durations"] = durations
    else:
        x509.pop("durations", None)  # the CA's defaults
    claims["disableRenewal"] = bool(changes.get("disable_renewal"))
    claims["allowRenewalAfterExpiry"] = bool(changes.get("allow_renewal_after_expiry"))

    if updated.get("type") == "ACME" and changes.get("acme") is not None:
        options = changes["acme"]
        acme = updated.setdefault("details", {}).setdefault("ACME", {})
        acme["forceCn"] = bool(options.get("force_cn"))
        acme["requireEab"] = bool(options.get("require_eab"))
        offered = [name for name, _ in ACME_CHALLENGES]
        # Challenges the form doesn't offer (e.g. device-attest-01) are kept as they are
        kept = [challenge for challenge in acme.get("challenges", []) if challenge not in offered]
        acme["challenges"] = [name for name in offered if name in (options.get("challenges") or [])] + kept

    if app_provisioner and updated.get("name") == app_provisioner:
        if not x509["enabled"]:
            raise ValueError("this is the app's own provisioner: it must keep issuing X.509 certificates")
        if "max" in durations and duration_seconds(durations["max"]) < APP_CERTIFICATE_HOURS * 3600:
            raise ValueError(f"this is the app's own provisioner: its maximum duration must stay at least {APP_CERTIFICATE_HOURS}h")
    return updated
