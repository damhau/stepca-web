"""The overview: certificate figures over a time range, what needs attention, recent activity, and how ready the
deployment is for production. Also the history of one certificate."""

from collections import Counter
from datetime import UTC, datetime, timedelta

from flask import current_app
from sqlalchemy import select

from app.auth.roles import current_role, role_at_least
from app.extensions import db
from app.libs.auth.ldap_backend import ldap_transport
from app.models.audit import AuditEvent
from app.services import acme, acme_inventory, ca, inventory, provisioners

RANGES = {"24h": (timedelta(hours=24), 24), "7d": (timedelta(days=7), 7), "30d": (timedelta(days=30), 30)}
# Points of each KPI's sparkline, from the start of the range to now
SPARK_POINTS = 8
# The provisioners the chart names; the others are added up as "Other"
CHART_SERIES = 2
# Sign-ins are left out of the activity: they would crowd out the changes
QUIET_ACTIONS = {"login", "logout"}


def now():
    return datetime.now(UTC)


def _points(start, end, count):
    step = (end - start) / (count - 1)
    return [start + step * i for i in range(count)]


def _windows(start, end, count):
    step = (end - start) / count
    return [(start + step * i, start + step * (i + 1)) for i in range(count)]


def kpis(span, when):
    start = when - span
    points = _points(start, when, SPARK_POINTS)
    windows = _windows(start, when, SPARK_POINTS - 1)
    return [
        {
            "key": "active",
            "label": "Active certificates",
            "value": inventory.valid_at(when),
            "previous": inventory.valid_at(start),
            "series": [inventory.valid_at(point) for point in points],
        },
        {
            "key": "issued",
            "label": "Issued",
            "value": inventory.issued_between(start, when),
            "previous": inventory.issued_between(start - span, start),
            "series": [inventory.issued_between(a, b) for a, b in windows],
        },
        {
            "key": "expiring",
            "label": "Expiring in 7 days",
            "value": inventory.expiring_at(when),
            "previous": inventory.expiring_at(start),
            "series": [inventory.expiring_at(point) for point in points],
        },
        {
            "key": "revoked",
            "label": "Revoked",
            "value": inventory.revoked_between(start, when),
            "previous": inventory.revoked_between(start - span, start),
            "series": [inventory.revoked_between(a, b) for a, b in windows],
        },
    ]


def issuance(span, buckets, when):
    """Certificates issued per bucket of the range, by provisioner: the CHART_SERIES biggest, then "Other"."""
    start = when - span
    windows = _windows(start, when, buckets)
    per_bucket = [inventory.issued_by_provisioner(a, b) for a, b in windows]
    totals: Counter = Counter()
    for counts in per_bucket:
        totals.update(counts)
    named = [name for name, _ in totals.most_common(CHART_SERIES)]
    series = named + (["Other"] if len(totals) > len(named) else [])
    return {
        "series": series,
        "total": sum(totals.values()),
        "buckets": [
            {
                "start": a,
                "end": b,
                "counts": [counts.get(name, 0) for name in named]
                + ([sum(v for k, v in counts.items() if k not in named)] if "Other" in series else []),
            }
            for (a, b), counts in zip(windows, per_bucket, strict=True)
        ],
    }


def callout(when):
    """What needs attention first: the long-lived certificate that ends soonest within 7 days (with its failed ACME
    renewals, if any), or else the ACME orders that failed in the last day. None when nothing does."""
    soonest, _ = inventory.certificates(inventory.CertificateQuery(status="expiring", days=7, sort="not_after", order="asc"), per_page=1)
    if soonest:
        cert = soonest[0]
        names = set(cert.dns_names) | ({cert.common_name} if cert.common_name else set())
        # Its renewals that failed, newest first
        failed = acme_inventory.failed_orders(cert.not_before, names) if cert.not_before else []
        latest = failed[0] if failed else None
        return {
            "kind": "expiring",
            "serial": cert.serial,
            "name": cert.common_name or cert.subject,
            "not_after": cert.not_after,
            "failed_renewals": len(failed),
            "error": latest.error if latest else None,
        }
    failed = acme_inventory.failed_orders(when - timedelta(days=1))
    if failed:
        latest = failed[0]
        return {
            "kind": "acme_failures",
            "serial": None,
            "name": ", ".join(identifier.value for identifier in latest.identifiers) or latest.id,
            "not_after": None,
            "failed_renewals": len(failed),
            "error": latest.error,
        }
    return None


def activity(limit=8):
    """Recent events: certificates issued (by their provisioner) and revoked, and, for admins, the audit log's changes."""
    events = []
    for item in inventory.recently_issued(limit):
        events.append(
            {
                "at": item.not_before,
                "actor": item.provisioner_name or "Unknown provisioner",
                "action": "issued",
                "subject": item.common_name or item.subject,
                "serial": item.serial,
            }
        )
    names = provisioners.names_by_id(include_deleted=True)
    for revocation, item in inventory.recently_revoked(limit):
        events.append(
            {
                "at": inventory.aware(revocation.revoked_at),
                "actor": names.get(revocation.provisioner_id, "Unknown provisioner"),
                "action": "revoked",
                "subject": (item.common_name or item.subject) if item else revocation.serial,
                "serial": revocation.serial if item else None,
            }
        )
    if role_at_least(current_role(), "admin"):
        audited = db.session.scalars(
            select(AuditEvent).where(AuditEvent.action.not_in(QUIET_ACTIONS), AuditEvent.success.is_(True)).order_by(AuditEvent.id.desc()).limit(limit)
        )
        for event in audited:
            # Revocations and signatures are already listed, by the provisioner: name the person instead
            if event.action in ("revoke", "sign"):
                for listed in events:
                    if listed["serial"] == event.target and listed["action"] == ("revoked" if event.action == "revoke" else "issued"):
                        listed["actor"] = event.user
                continue
            events.append(
                {
                    "at": event.created_at.replace(tzinfo=UTC) if event.created_at else None,
                    "actor": event.user,
                    "action": event.action.replace("_", " "),
                    "subject": event.target,
                    "serial": None,
                }
            )
    events = [event for event in events if event["at"]]
    return sorted(events, key=lambda event: event["at"], reverse=True)[:limit]


def overview(range_key):
    span, buckets = RANGES[range_key]
    when = now()
    inventory.refresh()
    return {
        "range": range_key,
        "kpis": kpis(span, when),
        "issuance": issuance(span, buckets, when),
        "callout": callout(when),
        "activity": activity(),
        "pending": inventory.pending(),
    }


def readiness():
    """Checks of the deployment against the recommended setup. done is None when it can't be told (CA unreachable)."""
    config = current_app.config
    client = ca.client()
    checks = []

    try:
        identity = provisioners.identity_type()
    except ca.CA_ERRORS:
        identity = None
    checks.append(
        {
            "key": "identity",
            "label": "Dedicated ADMIN identity for this app",
            "done": None if identity is None else identity == "ADMIN",
            "detail": f"The app acts on the CA as {client.subject}, a {identity}." if identity else "The CA could not be asked.",
        }
    )
    key_in_memory = client.admin_key_source().startswith("encrypted")
    checks.append(
        {
            "key": "key",
            "label": "Provisioner key kept off the disk",
            "done": key_in_memory,
            "detail": "Decrypted in memory from CA_ADMIN_PASSWORD_FILE." if key_in_memory else "jwk_key.json holds the decrypted key.",
        }
    )
    checks.append(
        {
            "key": "https",
            "label": "Served over HTTPS",
            "done": bool(config["SESSION_COOKIE_SECURE"]),
            "detail": "Secure session cookie and HSTS." if config["SESSION_COOKIE_SECURE"] else "Set SESSION_COOKIE_SECURE=true behind a TLS proxy.",
        }
    )
    if config["AUTH_BACKEND"] == "ldap":
        cleartext = ldap_transport(config) == "cleartext"
        checks.append(
            {
                "key": "ldap",
                "label": "Directory passwords sent over TLS",
                "done": not cleartext,
                "detail": "Use ldaps:// or LDAP_START_TLS=true." if cleartext else "LDAPS or StartTLS, server certificate verified.",
            }
        )
    else:
        checks.append(
            {
                "key": "roles",
                "label": "New users don't get the admin role",
                "done": config["DEFAULT_ROLE"] != "admin",
                "detail": f"DEFAULT_ROLE is {config['DEFAULT_ROLE']}.",
            }
        )
    try:
        crl = client.crl()
        checks.append(
            {
                "key": "crl",
                "label": "Revocation list published",
                "done": crl is not None,
                "detail": "step-ca publishes a CRL." if crl is not None else 'Set "crl": {"enabled": true} in ca.json.',
            }
        )
    except ca.CA_ERRORS:
        checks.append({"key": "crl", "label": "Revocation list published", "done": None, "detail": "The CA could not be asked."})
    try:
        intermediates = client.intermediates()
        days = min(((cert.not_valid_after_utc - now()).days for cert in intermediates), default=None)
        checks.append(
            {
                "key": "intermediate",
                "label": "Intermediate valid for 90 days or more",
                "done": days is not None and days >= 90,
                "detail": f"{days} days left." if days is not None else "The CA returned no intermediate.",
            }
        )
    except ca.CA_ERRORS:
        checks.append({"key": "intermediate", "label": "Intermediate valid for 90 days or more", "done": None, "detail": "The CA could not be asked."})
    return {"checks": checks}


def certificate_events(serial):
    """What happened to one certificate, newest first: its ACME order, issuance, revocation, expiry."""
    item = inventory.certificate(serial)
    if item is None:
        return None
    when = now()
    events = []
    if item.not_before:
        events.append({"at": item.not_before, "kind": "issued", "label": f"Issued by {item.provisioner_name or 'an unknown provisioner'}"})
    order_id = acme.order_id_for_serial(serial)
    if order_id:
        view = acme.order(order_id)
        if view:
            if view.order.created_at:
                events.append({"at": view.order.created_at, "kind": "info", "label": "ACME order placed"})
            for authorization in view.authorizations:
                for challenge in authorization.challenges:
                    if challenge.validated_at:
                        events.append(
                            {"at": challenge.validated_at, "kind": "ok", "label": f"{challenge.type} challenge validated for {challenge.value}"}
                        )
    if item.revoked_at:
        reason = item.revocation_reason or "no reason given"
        events.append({"at": item.revoked_at, "kind": "revoked", "label": f"Revoked: {reason}"})
    if item.not_after:
        ended = item.not_after <= when
        events.append({"at": item.not_after, "kind": "expired" if ended else "expires", "label": "Expired" if ended else "Expires"})
    if role_at_least(current_role(), "admin"):
        for event in db.session.scalars(select(AuditEvent).where(AuditEvent.target == serial).order_by(AuditEvent.id)):
            if event.created_at:
                events.append(
                    {
                        "at": event.created_at.replace(tzinfo=UTC),
                        "kind": "info" if event.success else "revoked",
                        "label": f"{event.action.replace('_', ' ').capitalize()} by {event.user}" + ("" if event.success else " (failed)"),
                    }
                )
    return sorted(events, key=lambda event: event["at"], reverse=True)
