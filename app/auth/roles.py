from functools import wraps

from flask import abort, session

# Ordered from least to most privileged
ROLES = ("viewer", "operator", "admin")


def role_at_least(role, minimum):
    return role in ROLES and ROLES.index(role) >= ROLES.index(minimum)


def current_role():
    return session.get("role")


def role_required(minimum):
    """Refuse (403) users below `minimum`."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not role_at_least(current_role(), minimum):
                abort(403)
            return f(*args, **kwargs)

        return wrapper

    return decorator


def resolve_role(user, config):
    """The role of a user returned by an auth backend, or None if it gets no access.

    Backends set `role` (local users) or `groups` (LDAP DNs). Groups are matched against
    ROLE_ADMIN_GROUP, ROLE_OPERATOR_GROUP and ROLE_VIEWER_GROUP, highest role first.
    Anyone else gets DEFAULT_ROLE ("viewer" unless set; "none" refuses them).
    """
    if user.get("role") in ROLES:
        return user["role"]
    groups = {group.lower() for group in user.get("groups", [])}
    for role in reversed(ROLES):
        group = config.get(f"ROLE_{role.upper()}_GROUP")
        if group and group.lower() in groups:
            return role
    default = config.get("DEFAULT_ROLE", "viewer")
    return default if default in ROLES else None
