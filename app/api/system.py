"""The CA's status and files, the configuration in effect, the audit log and the service control."""

import base64

from cryptography.hazmat.primitives import serialization
from flask import abort, current_app
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api import attribute, blueprint, contains, csv_response, dump, error, file_response, page, paginate
from app.api.schemas import AuditItem, AuditPage, AuditQuery, CaStatus, CrlQuery, Error, ServiceAction, ServiceResult, SettingsView
from app.auth.roles import role_required
from app.extensions import db
from app.models.audit import AuditEvent
from app.services import ca, system

bp = blueprint("api_system", "CA and system")

# The audit log the API reads, newest first
AUDIT_LIMIT = 10_000


def ca_certificate(described):
    return {**described, "serial": described["serial_dec"], "key": f"RSA {described['key_size']}" if isinstance(described["key_size"], int) else described["key_size"]}


@bp.get("/ca", responses={200: CaStatus}, summary="What step-ca reports about itself")
def ca_status():
    status = ca.ca_status()
    for kind in ("roots", "intermediates"):
        if status[kind] is not None:
            status[kind] = [ca_certificate(cert) for cert in status[kind]]
    return dump(CaStatus, {**status, "tested_versions": list(status["tested_versions"])})


class CertificatesPath(BaseModel):
    kind: str = Field(pattern="^(roots|intermediates)$")


@bp.get("/ca/<kind>.pem", responses={200: None, 404: Error, 502: Error}, summary="The CA's roots or intermediates, fetched from the CA")
def ca_certificates(path: CertificatesPath):
    certs = {"roots": ca.client().roots, "intermediates": ca.client().intermediates}[path.kind]()
    return file_response(b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs), f"{path.kind}.pem", "application/x-pem-file")


@bp.get("/ca/crl", responses={200: None, 404: Error, 502: Error}, summary="The CA's certificate revocation list")
def ca_crl(query: CrlQuery):
    der = ca.client().crl()
    if der is None:
        return error("step-ca doesn't publish a CRL.", 404)
    if query.format == "pem":
        pem = b"-----BEGIN X509 CRL-----\n" + base64.encodebytes(der) + b"-----END X509 CRL-----\n"
        return file_response(pem, "crl.pem", "application/x-pem-file")
    return file_response(der, "crl.crl", "application/pkix-crl")


@bp.get("/settings", responses={200: SettingsView})
@role_required("admin")
def settings():
    sections = [{"title": title, "items": [{"label": label, "value": "—" if value is None else str(value)} for label, value in items]} for title, items in system.effective_settings()]
    return dump(SettingsView, {"sections": sections, "warnings": system.config_warnings()})


AUDIT_CSV = [(name, attribute(name)) for name in ("created_at", "user", "role", "action", "target", "success", "detail")]


@bp.get("/audit", responses={200: AuditPage})
@role_required("admin")
def audit_log(query: AuditQuery):
    events = db.session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(AUDIT_LIMIT)).all()
    actions = sorted({event.action for event in events})
    rows = [
        event
        for event in events
        if contains(query.q, event.user, event.action, event.target, event.detail)
        and (query.action is None or event.action == query.action)
        and (query.success is None or event.success == query.success)
    ]
    if query.format == "csv":
        return csv_response("audit-log.csv", AUDIT_CSV, rows)
    items, total = paginate(rows, query)
    return page(AuditPage, [AuditItem.model_validate(event) for event in items], total, query, actions=actions)


@bp.post("/service", responses={200: ServiceResult, 500: ServiceResult}, summary="Start, stop, restart or query the step-ca service")
@role_required("admin")
def service(body: ServiceAction):
    if not current_app.config["SERVICE_CONTROL_ENABLED"]:
        abort(404)
    result = system.service_action(body.action)
    return dump(ServiceResult, result), 200 if result["success"] else 500
