import time

from app.libs.db_step import get_active_provisioner_map, get_step_provisioners
from app.libs.stepapi import StepCAClient
from config import CA_URL

# The one client shared by the whole app: one admin certificate, one decrypted key
client = StepCAClient(CA_URL)

# How long the app's admin type (ADMIN / SUPER_ADMIN) is cached
IDENTITY_CACHE_SECONDS = 300
# (fetched at, admin type). -inf, not 0: time.monotonic() counts from boot, so it can be under the cache lifetime
_identity = (float("-inf"), None)


def app_identity_type():
    """'SUPER_ADMIN' or 'ADMIN' for the app's own admin on the CA, None if unknown. Cached.

    The Admin API lists admins with a provisioner id, but lists provisioners without one:
    the id -> name mapping comes from step-ca's database.
    """
    global _identity
    fetched_at, admin_type = _identity
    if time.monotonic() - fetched_at < IDENTITY_CACHE_SECONDS:
        return admin_type
    admin_type = None
    admins = client.list_admins()
    if admins:
        provisioner_names = get_active_provisioner_map(get_step_provisioners())
        for admin in admins["admins"]:
            if admin.get("subject") == client.subject and provisioner_names.get(admin.get("provisioner_id")) == client.provisioner_name:
                admin_type = {1: "ADMIN", 2: "SUPER_ADMIN"}.get(admin.get("type"), admin.get("type"))
    _identity = (time.monotonic(), admin_type)
    return admin_type
