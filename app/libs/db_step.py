import base64
import json
import logging

from app.models.step import StepAdmin, StepProvisioner

log = logging.getLogger(__name__)




def get_step_provisioners():
    accounts = []
    for row in StepProvisioner.query.all():
        try:
            key = bytes(row.nkey).decode('utf-8', errors='ignore')
            value = json.loads(bytes(row.nvalue))

            details_bytes = base64.b64decode(value["details"])
            # Step 2: parse JSON
            details_json = json.loads(details_bytes)



            accounts.append({
                "nkey": key,
                "data": value,
                "details": details_json
            })
        except Exception as e:
            log.warning("Cannot parse provisioner: %s", e)
    return accounts


# linkedca.Provisioner_Type, the number step-ca stores as a provisioner's "type"
PROVISIONER_TYPES = {1: "JWK", 2: "OIDC", 3: "GCP", 4: "AWS", 5: "AZURE", 6: "ACME", 7: "X5C", 8: "K8SSA", 9: "SSHPOP", 10: "SCEP", 11: "NEBULA"}


def provisioner_type(provisioner):
    """The type name ("JWK", "ACME", ...) of a provisioner from get_step_provisioners()."""
    stored = provisioner["data"].get("type")
    return PROVISIONER_TYPES.get(stored, stored)


def get_jwk_provisioner_names(provisioners):
    """Active JWK provisioners: the only ones that sign a CSR with a password."""
    active = get_active_provisioner_map(provisioners)
    return sorted(p["data"]["name"] for p in provisioners if p["data"].get("id") in active and provisioner_type(p) == "JWK")


def get_active_provisioner_map(provisioners):
    """
    Returns a map (dictionary) where the key is the 'id' and the value is the 'name'
    from a list of provisioner data, excluding provisioners that have 'deletedAt' set
    to '0001-01-01T00:00:00Z'.

    :param provisioners: List of provisioner dictionaries
    :return: A dictionary with provisioner 'id' as the key and 'name' as the value
    """
    provisioner_map = {
        provisioner['data']['id']: provisioner['data']['name']
        for provisioner in provisioners
        if provisioner['data'].get('deletedAt', '') == '0001-01-01T00:00:00Z'
    }
    return provisioner_map


def get_admin_created_dates():
    """{admin id: createdAt} from step-ca's admins table. The Admin API leaves created_at out
    for admins added since the CA last started."""
    dates = {}
    for row in StepAdmin.query.all():
        try:
            admin = json.loads(bytes(row.nvalue))
            dates[admin["id"]] = admin.get("createdAt")
        except (ValueError, KeyError) as e:
            log.warning("Cannot parse admin: %s", e)
    return dates


def get_step_admins():
    """Admins that aren't deleted, from step-ca's admins table: subject, provisioner name and type."""
    names = get_active_provisioner_map(get_step_provisioners())
    admins = []
    for row in StepAdmin.query.all():
        try:
            data = json.loads(bytes(row.nvalue))
        except ValueError as e:
            log.warning("Cannot parse admin: %s", e)
            continue
        if data.get("deletedAt", "0001-01-01T00:00:00Z").startswith("0001-01-01"):
            admins.append({"subject": data.get("subject", ""), "provisioner": names.get(data.get("provisionerID"), "—"), "type": data.get("type")})
    return admins
