import logging

from ldap3 import ALL, SIMPLE, SUBTREE, Connection, Server
from ldap3.utils.conv import escape_filter_chars

from .base import AuthBackend

log = logging.getLogger(__name__)




class LDAPAuthBackend(AuthBackend):
    def __init__(self, config):
        self.config = config
        self.ldap_url = config.get('LDAP_URL', 'ldap://localhost')
        self.base_dn = config.get('LDAP_BASE_DN', '')
        self.domain = config.get('LDAP_DOMAIN', '')
        self.user_search_filter = config.get('LDAP_USER_SEARCH_FILTER', '(uid={username})')
        self.user_search_base = config.get('LDAP_USER_SEARCH_BASE', self.base_dn)
        self.required_group_dn = config.get('LDAP_REQUIRED_GROUP_DN')

    def authenticate(self, username, password):
        # An empty password would be an anonymous bind, which many servers accept
        if not username or not password:
            return None
        ldap_user = username + "@" + self.domain
        try:

            server = Server(self.ldap_url, get_info=ALL)

            conn = Connection(server, user=ldap_user, password=password, authentication=SIMPLE, auto_bind=True)
            if conn.bound:

                conn.search(
                    search_base=self.user_search_base,
                    search_filter=self.user_search_filter.format(username=escape_filter_chars(username)),
                    search_scope=SUBTREE,
                    attributes=['*']
                )

                user_info = conn.entries[0] if conn.entries else None
                conn.unbind()
                if not user_info:
                    return None
                member_of = user_info.entry_attributes_as_dict.get('memberOf', [])
                # memberOf can be a string or list
                if isinstance(member_of, str):
                    member_of = [member_of]
                if self.required_group_dn and self.required_group_dn not in member_of:
                    return None  # Not a member of required group
                # Group DNs are mapped to roles by resolve_role()
                return {'id': username, 'dn': user_info.entry_dn, 'groups': member_of}
            return None
        except Exception as e:
            log.warning("LDAP authentication of %s failed: %s", username, e)
            return None

    def get_user(self, user_id):
        try:
            server = Server(self.ldap_url, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            conn.search(
                search_base=self.user_search_base,
                search_filter=self.user_search_filter.format(username=escape_filter_chars(user_id)),
                search_scope=SUBTREE,
                attributes=['*']
            )
            user_info = conn.entries[0] if conn.entries else None
            conn.unbind()
            if user_info:
                return {'id': user_id, 'attributes': user_info.entry_attributes_as_dict}
            return None
        except Exception:
            return None
