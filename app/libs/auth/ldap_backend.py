import logging
import ssl
from urllib.parse import urlparse

from ldap3 import ALL, AUTO_BIND_TLS_BEFORE_BIND, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from .base import AuthBackend

log = logging.getLogger(__name__)


def ldap_transport(config):
    """How passwords travel to the LDAP server: "ldaps", "starttls" or "cleartext"."""
    if urlparse(config.get('LDAP_URL') or '').scheme.lower() == 'ldaps':
        return 'ldaps'
    return 'starttls' if config.get('LDAP_START_TLS') else 'cleartext'


class LDAPAuthBackend(AuthBackend):
    def __init__(self, config):
        self.config = config
        self.ldap_url = config.get('LDAP_URL', 'ldap://localhost')
        self.base_dn = config.get('LDAP_BASE_DN', '')
        self.domain = config.get('LDAP_DOMAIN', '')
        self.bind_dn = config.get('LDAP_BIND_DN')
        self.start_tls = config.get('LDAP_START_TLS', False)
        self.user_search_filter = config.get('LDAP_USER_SEARCH_FILTER', '(uid={username})')
        self.user_search_base = config.get('LDAP_USER_SEARCH_BASE', self.base_dn)
        self.required_group_dn = config.get('LDAP_REQUIRED_GROUP_DN')
        # ldap3 does not check the server certificate unless told to: always check it, against
        # LDAP_CA_FILE or else the system CAs (used by ldaps:// and StartTLS)
        self.tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=config.get('LDAP_CA_FILE') or None)

    def _bind_name(self, username):
        if self.bind_dn:
            # A DN template, e.g. uid={username},ou=people,dc=example,dc=org
            return self.bind_dn.format(username=escape_rdn(username))
        # The user principal name, as Active Directory accepts it
        return username + "@" + self.domain

    def authenticate(self, username, password):
        # An empty password would be an anonymous bind, which many servers accept
        if not username or not password:
            return None
        server = Server(self.ldap_url, get_info=ALL, tls=self.tls)
        try:
            conn = Connection(
                server,
                user=self._bind_name(username),
                password=password,
                authentication=SIMPLE,
                auto_bind=AUTO_BIND_TLS_BEFORE_BIND if self.start_tls else True,
            )
        except LDAPBindError:
            return None  # wrong username or password
        except LDAPException as e:
            # Unreachable server, or a TLS certificate that doesn't verify
            log.error("Cannot connect to the LDAP server %s: %s", self.ldap_url, e)
            return None

        try:
            # memberOf is an operational attribute on OpenLDAP: only returned when asked for by name
            attributes = ['*']
            if server.schema and 'memberOf' in server.schema.attribute_types:
                attributes.append('memberOf')
            conn.search(
                search_base=self.user_search_base,
                search_filter=self.user_search_filter.format(username=escape_filter_chars(username)),
                search_scope=SUBTREE,
                attributes=attributes,
            )
            user_info = conn.entries[0] if conn.entries else None
        except LDAPException as e:
            log.error("LDAP search for %s failed: %s", username, e)
            return None
        finally:
            conn.unbind()

        if not user_info:
            return None
        member_of = user_info.entry_attributes_as_dict.get('memberOf', [])
        # memberOf can be a string or list
        if isinstance(member_of, str):
            member_of = [member_of]
        # DNs compare case-insensitively, as in resolve_role()
        if self.required_group_dn and self.required_group_dn.lower() not in {group.lower() for group in member_of}:
            return None  # Not a member of required group
        # Group DNs are mapped to roles by resolve_role()
        return {'id': username, 'dn': user_info.entry_dn, 'groups': member_of}
