"""Single sign-on with OpenID Connect: the authorization code flow with PKCE.

The app is a confidential client. `start()` builds the redirect to the identity provider and returns what
must be remembered until it comes back (state, nonce, PKCE verifier); `finish()` checks the answer, swaps the
code for tokens and validates the ID token (signature, issuer, audience, expiry, nonce). The result has the
same shape as the other backends' users: {'id': ..., 'groups': [...]} and optionally 'role'.
"""

import base64
import hashlib
import logging
import secrets
import threading
import time
from urllib.parse import quote_plus, urlencode

import jwt
import requests
from requests.auth import HTTPBasicAuth

log = logging.getLogger(__name__)

# Asymmetric algorithms only: an ID token signed with a shared secret (HS256) or not at all is never accepted
ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]
TIMEOUT = 10
# Seconds of clock difference between this server and the identity provider that are tolerated
LEEWAY = 60
DISCOVERY_TTL = 3600


class OIDCError(Exception):
    """The sign-in failed. The message is for the log, never for the browser."""


def _pkce_challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def _as_list(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else [str(item) for item in value]


class OIDCClient:
    def __init__(self, config):
        self.issuer = (config.get("OIDC_ISSUER") or "").rstrip("/")
        self.client_id = config.get("OIDC_CLIENT_ID") or ""
        self.client_secret = config.get("OIDC_CLIENT_SECRET") or ""
        self.scopes = config.get("OIDC_SCOPES") or "openid profile email"
        self.username_claim = config.get("OIDC_USERNAME_CLAIM") or "preferred_username"
        self.groups_claim = config.get("OIDC_GROUPS_CLAIM") or "groups"
        self.required_group = config.get("OIDC_REQUIRED_GROUP")
        self.verify = config.get("OIDC_CA_FILE") or True
        self._discovery = None
        self._discovered_at = 0.0
        self._jwks = None
        self._lock = threading.Lock()

    # --- The identity provider's metadata ------------------------------------------------------------

    def discovery(self):
        """The provider's /.well-known/openid-configuration, cached for an hour."""
        with self._lock:
            if self._discovery and time.monotonic() - self._discovered_at < DISCOVERY_TTL:
                return self._discovery
            try:
                response = requests.get(f"{self.issuer}/.well-known/openid-configuration", timeout=TIMEOUT, verify=self.verify)
                response.raise_for_status()
                document = response.json()
            except (requests.RequestException, ValueError) as e:
                raise OIDCError(f"Cannot read the discovery document of {self.issuer}: {e}") from e
            # Mix-up defence: the document must be the one of the issuer we were configured with
            if str(document.get("issuer", "")).rstrip("/") != self.issuer:
                raise OIDCError(f"The discovery document names the issuer {document.get('issuer')!r}, not {self.issuer!r}")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not document.get(key):
                    raise OIDCError(f"The discovery document has no {key}")
            self._discovery = document
            self._discovered_at = time.monotonic()
            self._jwks = jwt.PyJWKClient(document["jwks_uri"], cache_keys=True, timeout=TIMEOUT)
            return document

    # --- Step 1: send the browser to the provider ----------------------------------------------------

    def start(self, redirect_uri):
        """(URL to send the browser to, what to keep in the session until it comes back)."""
        metadata = self.discovery()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": _pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        separator = "&" if "?" in metadata["authorization_endpoint"] else "?"
        return f"{metadata['authorization_endpoint']}{separator}{urlencode(query)}", {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
        }

    # --- Step 2: the browser comes back with a code --------------------------------------------------

    def finish(self, params, pending, redirect_uri):
        """The user for the provider's answer (the query of the callback), or OIDCError."""
        if params.get("error"):
            raise OIDCError(f"The provider refused the sign-in: {params['error']} {params.get('error_description', '')}".strip())
        if not pending:
            raise OIDCError("No sign-in was started from this browser (or it took too long)")
        returned_state = params.get("state") or ""
        if not secrets.compare_digest(returned_state.encode(), str(pending["state"]).encode()):
            raise OIDCError("The state does not match: the answer is not for the sign-in started here")
        code = params.get("code")
        if not code:
            raise OIDCError("The answer has no code")

        tokens = self._exchange(code, pending["verifier"], redirect_uri)
        claims = self._validate(tokens, pending["nonce"])
        return self._user(claims, tokens)

    def _exchange(self, code, verifier, redirect_uri):
        metadata = self.discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "code_verifier": verifier,
        }
        auth = None
        methods = metadata.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        if self.client_secret:
            if "client_secret_basic" in methods:
                auth = HTTPBasicAuth(quote_plus(self.client_id), quote_plus(self.client_secret))
            else:
                data["client_secret"] = self.client_secret
        try:
            response = requests.post(metadata["token_endpoint"], data=data, auth=auth, timeout=TIMEOUT, verify=self.verify)
        except requests.RequestException as e:
            raise OIDCError(f"Cannot reach the token endpoint: {e}") from e
        if response.status_code != 200:
            # The body names the problem (invalid_grant, invalid_client, ...) and holds no secret
            raise OIDCError(f"The token endpoint answered {response.status_code}: {response.text[:300]}")
        try:
            tokens = response.json()
        except ValueError as e:
            raise OIDCError("The token endpoint did not answer with JSON") from e
        if not tokens.get("id_token"):
            raise OIDCError("The token endpoint returned no id_token")
        return tokens

    def _validate(self, tokens, nonce):
        metadata = self.discovery()
        id_token = tokens["id_token"]
        try:
            algorithm = jwt.get_unverified_header(id_token).get("alg")
            if algorithm not in ALGORITHMS:
                raise OIDCError(f"The ID token is signed with {algorithm}, which is not accepted")
            key = self._signing_key(id_token)
            claims = jwt.decode(
                id_token,
                key,
                algorithms=ALGORITHMS,
                audience=self.client_id,
                # Exactly the issuer the provider announces: the token's iss must be the same string
                issuer=metadata["issuer"],
                leeway=LEEWAY,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as e:
            raise OIDCError(f"The ID token is not valid: {e}") from e
        # One client id in the audience is not enough when there are several: the token must be for us
        audience = _as_list(claims.get("aud"))
        if len(audience) > 1 and claims.get("azp") != self.client_id:
            raise OIDCError("The ID token has several audiences and was not issued to this client (azp)")
        if not secrets.compare_digest(str(claims.get("nonce", "")).encode(), nonce.encode()):
            raise OIDCError("The nonce of the ID token does not match: replayed token")
        return claims

    def _signing_key(self, id_token):
        jwks = self._jwks
        if jwks is None:
            raise OIDCError("The provider's signing keys are not loaded")
        return jwks.get_signing_key_from_jwt(id_token).key

    def _user(self, claims, tokens):
        # Providers differ in what the ID token holds: the userinfo endpoint fills the gaps
        if self.username_claim not in claims or (self.groups_claim and self.groups_claim not in claims):
            claims = {**self._userinfo(tokens, claims), **claims}
        username = claims.get(self.username_claim)
        if not isinstance(username, str) or not username.strip():
            raise OIDCError(f"The token has no usable '{self.username_claim}' claim")
        groups = _as_list(claims.get(self.groups_claim)) if self.groups_claim else []
        if self.required_group and self.required_group.lower() not in {group.lower() for group in groups}:
            raise OIDCError(f"{username} is not a member of the required group")
        return {"id": username.strip(), "groups": groups, "attributes": {"sub": claims["sub"], "email": claims.get("email")}}

    def _userinfo(self, tokens, claims):
        endpoint = (self._discovery or {}).get("userinfo_endpoint")
        access_token = tokens.get("access_token")
        if not endpoint or not access_token:
            return {}
        try:
            response = requests.get(endpoint, headers={"Authorization": f"Bearer {access_token}"}, timeout=TIMEOUT, verify=self.verify)
            response.raise_for_status()
            info = response.json()
        except (requests.RequestException, ValueError) as e:
            log.warning("Cannot read the userinfo endpoint: %s", e)
            return {}
        # Another user's data is never merged in: the subject must be the one of the ID token
        return info if info.get("sub") == claims.get("sub") else {}

