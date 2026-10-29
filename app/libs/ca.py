import logging
import time
from datetime import UTC, datetime

import requests
from cryptography import x509
from flask import current_app

from app.libs.cert_utils import describe_certificate, fingerprint
from app.libs.db_step import get_active_provisioner_map, get_step_provisioners
from app.libs.stepapi import StepCAClient

log = logging.getLogger(__name__)



def client() -> StepCAClient:
    """The app's one CA client (built by create_app): one admin certificate, one decrypted key."""
    return current_app.extensions["stepca"]


# How long the app's admin type (ADMIN / SUPER_ADMIN) is cached
IDENTITY_CACHE_SECONDS = 300


def app_identity_type():
    """'SUPER_ADMIN' or 'ADMIN' for the app's own admin on the CA, None if unknown. Cached.

    The Admin API lists admins with a provisioner id, but lists provisioners without one:
    the id -> name mapping comes from step-ca's database.
    """
    ca = client()
    # -inf at first, not 0: time.monotonic() counts from boot, so it can be under the cache lifetime
    fetched_at, admin_type = ca.identity_cache
    if time.monotonic() - fetched_at < IDENTITY_CACHE_SECONDS:
        return admin_type
    admin_type = None
    admins = ca.list_admins()
    if admins:
        provisioner_names = get_active_provisioner_map(get_step_provisioners())
        for admin in admins["admins"]:
            if admin.get("subject") == ca.subject and provisioner_names.get(admin.get("provisioner_id")) == ca.provisioner_name:
                admin_type = {1: "ADMIN", 2: "SUPER_ADMIN"}.get(admin.get("type"), admin.get("type"))
    ca.identity_cache = (time.monotonic(), admin_type)
    return admin_type


# step-ca versions (major.minor) the end-to-end tests run against: tests/e2e/compose.yml
TESTED_STEP_CA_VERSIONS = ("0.30",)
# What can go wrong when asking the CA: unreachable, TLS or fingerprint mismatch, unexpected answer
CA_ERRORS = (requests.RequestException, ConnectionError, ValueError, KeyError)


def version_is_tested(version):
    return any(version == tested or version.startswith(tested + ".") for tested in TESTED_STEP_CA_VERSIONS)


def check_ca_version(ca):
    """Log step-ca's version, with a warning when the app isn't tested with it. Run once at startup."""
    try:
        version = ca.version()["version"]
    except CA_ERRORS as e:
        log.warning("Cannot read step-ca's version: %s", e)
        return None
    if version_is_tested(version):
        log.info("step-ca %s", version)
    else:
        log.warning("step-ca %s: this app is tested with step-ca %s, some pages may not work", version, ", ".join(TESTED_STEP_CA_VERSIONS))
    return version


def describe_ca_certificate(cert, pinned=None):
    days_left = (cert.not_valid_after_utc - datetime.now(UTC)).days
    return {**describe_certificate(cert), "fingerprint": fingerprint(cert), "days_left": days_left, "pinned": fingerprint(cert) == pinned}


def describe_crl(der):
    crl = x509.load_der_x509_crl(der)
    return {
        "issuer": crl.issuer.rfc4514_string(),
        "entries": len(crl),
        "this_update": crl.last_update_utc.isoformat(),
        "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
    }


def ca_status():
    """What step-ca reports about itself, for the status page. Each part is None when it can't be read."""
    ca = client()
    status = {"url": ca.ca_url, "errors": []}
    parts = {
        "health": lambda: ca.health().get("status"),
        "version": lambda: ca.version()["version"],
        "roots": lambda: [describe_ca_certificate(cert, ca.ca_fingerprint) for cert in ca.roots()],
        "intermediates": lambda: [describe_ca_certificate(cert) for cert in ca.intermediates()],
        "crl": lambda: describe_crl(der) if (der := ca.crl()) else None,
    }
    for name, read in parts.items():
        try:
            status[name] = read()
        except CA_ERRORS as e:
            status[name] = None
            status["errors"].append(f"{name}: {e}")
    status["version_tested"] = bool(status["version"]) and version_is_tested(status["version"])
    status["tested_versions"] = TESTED_STEP_CA_VERSIONS
    return status
