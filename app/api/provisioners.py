"""Provisioners and admins, through step-ca's Admin API (services.provisioners says which source is used for what)."""

from app.api import blueprint, dump, error
from app.api.schemas import (
    AdminCreate,
    AdminList,
    AdminUpdate,
    Done,
    Error,
    IdPath,
    NamePath,
    ProvisionerCreate,
    ProvisionerItem,
    ProvisionerList,
    ProvisionerUpdate,
)
from app.auth.roles import role_required
from app.libs.audit import audit
from app.libs.provisioners import apply_changes
from app.services import ca, provisioners
from app.stepca.client import CAError

bp = blueprint("api_provisioners", "Provisioners and admins")

ADMIN_TYPE_CODES = {"ADMIN": 1, "SUPER_ADMIN": 2}


@bp.get("/provisioners", responses={200: ProvisionerList, 502: Error})
def list_provisioners():
    listed = ca.client().list_provisioners()
    if listed is None:
        return error("Could not load the provisioners from the CA.", 502)
    return dump(ProvisionerList, {"provisioners": provisioners.summaries(listed["provisioners"])})


@bp.get("/provisioners/<name>", responses={200: ProvisionerItem, 404: Error})
def get_provisioner(path: NamePath):
    found = ca.client().get_provisioner(path.name)
    if found is None:
        return error(f"Provisioner '{path.name}' not found.", 404)
    return dump(ProvisionerItem, provisioners.summaries([found])[0])


@bp.post("/provisioners", responses={201: Done, 422: Error})
@role_required("admin")
def create_provisioner(body: ProvisionerCreate):
    durations = body.durations.model_dump(exclude_none=True)
    claims = {"x509": {"enabled": True, **({"durations": durations} if durations else {})}}
    try:
        if body.type == "JWK":
            if not body.password:
                return error("A JWK provisioner needs a password to encrypt its key.", 422)
            ca.client().create_provisioner_jwk(body.name, body.password, claims=claims)
        else:
            acme = body.acme.model_dump() if body.acme else {}
            details = {
                "ACME": {
                    "requireEab": acme.get("require_eab", False),
                    "forceCn": acme.get("force_cn", False),
                    "challenges": acme.get("challenges", []),
                }
            }
            ca.client().create_provisioner_acme(name=body.name, details=details, claims=claims)
    except CAError as e:
        audit("create_provisioner", body.name, success=False, detail=f"{body.type} {e}")
        return error(f"step-ca did not create the provisioner: {e}", 422)
    audit("create_provisioner", body.name, detail=body.type)
    return dump(Done, {"message": f"Provisioner '{body.name}' created."}), 201


@bp.put("/provisioners/<name>", responses={200: ProvisionerItem, 404: Error, 422: Error})
@role_required("admin")
def update_provisioner(path: NamePath, body: ProvisionerUpdate):
    client = ca.client()
    current = client.get_provisioner(path.name)
    if current is None:
        return error(f"Provisioner '{path.name}' not found.", 404)
    changes = body.model_dump()
    changes["durations"] = body.durations.model_dump(exclude_none=True)
    try:
        updated = client.update_provisioner(path.name, apply_changes(current, changes, app_provisioner=client.provisioner_name))
    except (ValueError, CAError) as e:
        audit("update_provisioner", path.name, success=False, detail=str(e))
        return error(f"Provisioner '{path.name}' was not updated: {e}", 422)
    audit("update_provisioner", path.name)
    return dump(ProvisionerItem, provisioners.summaries([updated])[0])


@bp.delete("/provisioners/<name>", responses={200: Done, 422: Error})
@role_required("admin")
def delete_provisioner(path: NamePath):
    if path.name == ca.client().provisioner_name:
        return error("This is the app's own provisioner: deleting it would lock the app out of the CA.", 422)
    try:
        ca.client().delete_provisioner(path.name)
    except CAError as e:
        audit("delete_provisioner", path.name, success=False, detail=str(e))
        return error(f"step-ca did not delete the provisioner: {e}", 422)
    audit("delete_provisioner", path.name)
    return dump(Done, {"message": f"Provisioner '{path.name}' deleted."})


@bp.get("/admins", responses={200: AdminList, 502: Error})
def list_admins():
    listed = ca.client().list_admins()
    if listed is None:
        return error("Could not load the admins from the CA.", 502)
    return dump(
        AdminList,
        {
            "admins": provisioners.admin_rows(listed["admins"]),
            "manageable": provisioners.admins_manageable(),
            "identity_type": provisioners.identity_type(),
            "provisioners": [{"id": provisioner_id, "name": name} for provisioner_id, name in sorted(provisioners.names_by_id().items(), key=lambda item: item[1])],
        },
    )


def refused_unless_manageable():
    if provisioners.admins_manageable():
        return None
    return error("The app's identity on the CA is not a SUPER_ADMIN: manage admins with `step ca admin`.", 403)


@bp.post("/admins", responses={201: Done, 403: Error, 422: Error})
@role_required("admin")
def create_admin(body: AdminCreate):
    if refused := refused_unless_manageable():
        return refused
    detail = f"provisioner={body.provisioner} type={body.type}"
    try:
        ca.client().create_admin(subject=body.subject, provisioner=body.provisioner, admin_type=ADMIN_TYPE_CODES[body.type])
    except CAError as e:
        audit("create_admin", body.subject, success=False, detail=f"{detail} {e}")
        return error(f"step-ca did not create the admin: {e}", 422)
    audit("create_admin", body.subject, detail=detail)
    return dump(Done, {"message": f"Admin '{body.subject}' created."}), 201


@bp.patch("/admins/<id>", responses={200: Done, 403: Error, 422: Error})
@role_required("admin")
def update_admin(path: IdPath, body: AdminUpdate):
    if refused := refused_unless_manageable():
        return refused
    try:
        ca.client().update_admin(path.id, ADMIN_TYPE_CODES[body.type])
    except CAError as e:
        audit("update_admin", path.id, success=False, detail=f"type={body.type} {e}")
        return error(f"step-ca did not update the admin: {e}", 422)
    audit("update_admin", path.id, detail=f"type={body.type}")
    return dump(Done, {"message": "Admin updated."})


@bp.delete("/admins/<id>", responses={200: Done, 403: Error, 422: Error})
@role_required("admin")
def delete_admin(path: IdPath):
    if refused := refused_unless_manageable():
        return refused
    try:
        ca.client().delete_admin(path.id)
    except CAError as e:
        audit("delete_admin", path.id, success=False, detail=str(e))
        return error(f"step-ca did not delete the admin: {e}", 422)
    audit("delete_admin", path.id)
    return dump(Done, {"message": "Admin deleted."})
