import base64
import json
import logging

from app.models.step import StepProvisioner

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
