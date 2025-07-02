from .base import AuthBackend
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE

class LDAPAuthBackend(AuthBackend):
    def __init__(self, config):
        self.config = config
        self.ldap_url = config.get('LDAP_URL', 'ldap://localhost')
        self.base_dn = config.get('LDAP_BASE_DN', '')
        self.user_dn_template = config.get('LDAP_USER_DN_TEMPLATE', 'uid={username},' + self.base_dn)
        self.user_search_filter = config.get('LDAP_USER_SEARCH_FILTER', '(uid={username})')
        self.user_search_base = config.get('LDAP_USER_SEARCH_BASE', self.base_dn)

    def authenticate(self, username, password):
        user_dn = self.user_dn_template.format(username=username)
        try:
            server = Server(self.ldap_url, get_info=ALL)
            conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE, auto_bind=True)
            if conn.bound:
                conn.search(
                    search_base=self.user_search_base,
                    search_filter=self.user_search_filter.format(username=username),
                    search_scope=SUBTREE,
                    attributes=['*']
                )
                user_info = conn.entries[0] if conn.entries else None
                conn.unbind()
                if user_info:
                    return {'id': username, 'dn': user_dn, 'attributes': user_info.entry_attributes_as_dict}
                else:
                    return {'id': username, 'dn': user_dn}
            return None
        except Exception as e:
            return None

    def get_user(self, user_id):
        try:
            server = Server(self.ldap_url, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            conn.search(
                search_base=self.user_search_base,
                search_filter=self.user_search_filter.format(username=user_id),
                search_scope=SUBTREE,
                attributes=['*']
            )
            user_info = conn.entries[0] if conn.entries else None
            conn.unbind()
            if user_info:
                return {'id': user_id, 'attributes': user_info.entry_attributes_as_dict}
            return None
        except Exception as e:
            return None
