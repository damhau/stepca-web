import base64
import fcntl
import json
import logging
import os
import secrets
import tempfile
import threading
import time
import uuid
import warnings
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urljoin

import jwt as python_jwt
import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jwcrypto import jwa
from jwcrypto import jwe as jwcrypto_jwe
from jwcrypto import jwk as jwcrypto_jwk
from jwt.algorithms import ECAlgorithm

from app.libs.cert_utils import extract_sans_from_csr, issuing_provisioner
from config import CA_ADMIN_PASSWORD, CA_ADMIN_PASSWORD_FILE, CA_ADMIN_PROVISIONER_NAME, CA_ADMIN_SUBJECT, CA_FINGERPRINT, CA_ROOT

# step encrypts provisioner keys with PBES2 and 600,000 iterations; jwcrypto refuses more than its own small
# default to stop a malicious server from burning CPU, so raise the cap just enough
jwa.default_max_pbkdf2_iterations = 1_000_000

log = logging.getLogger(__name__)

# Seconds before a request to the CA is abandoned
TIMEOUT = 30
class CAToken:
    def __init__(self, ca_url, ca_path, ca_fingerprint, provisioner_name, subject, jwk_privkey, sans=None):
        self.ca_url = ca_url
        self.ca_path = ca_path
        self.ca_fingerprint = ca_fingerprint
        self.provisioner_name = provisioner_name
        self.subject = subject
        self.sans = sans

        key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(jwk_privkey)
        self.token = python_jwt.encode(self.jwt_body(), key=key, headers={"kid": jwk_privkey["kid"]}, algorithm="ES256")

    def jwt_body(self):
        body = {
            "aud": urljoin(self.ca_url, self.ca_path),
            "sha": self.ca_fingerprint,
            "exp": datetime.now(tz=UTC) + timedelta(minutes=5),
            "iat": datetime.now(tz=UTC),
            "nbf": datetime.now(tz=UTC),
            "jti": str(uuid.uuid4()),
            "iss": self.provisioner_name,
            "sub": self.subject,
        }

        if self.sans:
            body["sans"] = self.sans

        return body


class StepCAClient:
    def __init__(
        self,
        ca_url,
        cert_file="admin.crt",
        key_file="admin.key",
        subject=CA_ADMIN_SUBJECT,
        provisioner_name=CA_ADMIN_PROVISIONER_NAME,
        not_after="24h",
    ):
        self.ca_url = ca_url.rstrip("/")
        self.cert_file = cert_file
        self.key_file = key_file
        self.subject = subject
        self.provisioner_name = provisioner_name
        self.not_after = not_after
        # The admin provisioner's private key, decrypted in memory on first use (see _admin_jwk)
        self._jwk = None
        self._jwk_lock = threading.Lock()
        # CA root that TLS is verified against: CA_ROOT if set, else bootstrapped from CA_FINGERPRINT
        self.ca_fingerprint = (CA_FINGERPRINT or "").replace(":", "").lower()
        self.root_file = CA_ROOT or "ca_root.crt"
        self._root_verified = bool(CA_ROOT)

    def _compare_fingerprints(self, pem, fingerprint):
        cert = x509.load_pem_x509_certificate(str.encode(pem))
        if cert.fingerprint(hashes.SHA256()) != bytes.fromhex(fingerprint):
            raise ConnectionError("WARNING: fingerprints do not match")

    def _ca_root(self):
        """Path of the CA root every request is verified against.

        Like `step ca bootstrap`: download the root once, check that it matches
        CA_FINGERPRINT, then keep it in the working directory.
        """
        if self._root_verified:
            return self.root_file
        if not self.ca_fingerprint:
            raise ConnectionError("Set CA_FINGERPRINT (or CA_ROOT) to verify the CA's TLS certificate")

        if os.path.exists(self.root_file):
            try:
                with open(self.root_file) as f:
                    self._compare_fingerprints(f.read(), self.ca_fingerprint)
                self._root_verified = True
                return self.root_file
            except (ConnectionError, ValueError):
                pass  # root of another CA: download it again

        # The root isn't trusted yet, so this request can't be verified: the fingerprint check protects it
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            resp = requests.get(f"{self.ca_url}/root/{self.ca_fingerprint}", verify=False, timeout=TIMEOUT)
        resp.raise_for_status()
        pem = resp.json()["ca"]
        self._compare_fingerprints(pem, self.ca_fingerprint)

        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(self.root_file)))
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        os.replace(tmp, self.root_file)
        log.info("CA root verified against the fingerprint and saved to %s", self.root_file)
        self._root_verified = True
        return self.root_file

    def admin_key_source(self):
        if CA_ADMIN_PASSWORD_FILE or CA_ADMIN_PASSWORD:
            return "encrypted key from the CA, decrypted in memory"
        return "jwk_key.json (decrypted key on disk, legacy)"

    def _admin_jwk(self):
        """The private JWK of the admin provisioner, used for the admin certificate and for revocations.

        With CA_ADMIN_PASSWORD_FILE (or CA_ADMIN_PASSWORD), the provisioner's encrypted key is fetched
        from the CA and decrypted in memory: no plaintext key on disk. Otherwise jwk_key.json is read.
        """
        with self._jwk_lock:
            if self._jwk is None:
                if CA_ADMIN_PASSWORD_FILE or CA_ADMIN_PASSWORD:
                    password = CA_ADMIN_PASSWORD
                    if CA_ADMIN_PASSWORD_FILE:
                        with open(CA_ADMIN_PASSWORD_FILE) as f:
                            password = f.read().strip()
                    provisioner = self.public_get_provisioner_by_name(self.provisioner_name)
                    self._jwk = self.decrypt_and_merge(jwk_public=provisioner["key"], encrypted_key=provisioner["encryptedKey"], passphrase=password)
                    log.info("Key of provisioner '%s' decrypted in memory", self.provisioner_name)
                else:
                    self._jwk = self._load_jwk_key_from_file("jwk_key.json")
                    if self._jwk is None:
                        raise RuntimeError("Set CA_ADMIN_PASSWORD_FILE (or provide jwk_key.json) to act on the CA")
            return self._jwk

    def _load_jwk_key_from_file(self, filename):
        try:
            with open(filename) as json_file:
                jwk_key = json.load(json_file)
            log.warning("Using the decrypted key in %s: set CA_ADMIN_PASSWORD_FILE to keep it off the disk", filename)
            return jwk_key
        except FileNotFoundError:
            return None

    def _is_cert_valid(self, cert_path, min_validity_hours=1):
        """Valid for at least another hour, and issued to the configured subject by the configured
        provisioner: after switching identity, a certificate of the old one must not be reused."""
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        common_names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        return (
            cert.not_valid_after_utc - datetime.now(UTC) > timedelta(hours=min_validity_hours)
            and common_names == [self.subject]
            and issuing_provisioner(cert) == self.provisioner_name
        )

    @staticmethod
    def _write_atomic(path, content, mode=0o644):
        """Write a file in one step, so a reader never sees it half written."""
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)

    def _admin_credentials(self):
        """The admin certificate chain and key, renewed when missing or close to expiry.

        A file lock stops several gunicorn workers from renewing at the same time, and from
        reading a certificate and a key that come from two different renewals.
        """
        with open(f"{self.cert_file}.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if not (os.path.exists(self.cert_file) and os.path.exists(self.key_file) and self._is_cert_valid(self.cert_file)):
                log.info("No valid admin certificate for '%s' from '%s': requesting one", self.subject, self.provisioner_name)
                self._request_new_certificate()
            with open(self.cert_file, "rb") as f:
                pem_cert = f.read()
            with open(self.key_file, "rb") as f:
                pem_key = f.read()
        return pem_cert, pem_key

    def _request_new_certificate(self):
        """Get the app's admin certificate from the CA with a one-time token of the admin provisioner."""
        # --- Generate Subject Key & CSR ---
        subject_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.subject)]))
            .sign(subject_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        # --- Generate JWT (OTT) ---
        aud = f"{self.ca_url}/sign"
        now = int(time.time())
        jwt_payload = {
            "iss": self.provisioner_name,
            "sub": self.subject,
            "aud": aud,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "jti": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
        }

        admin_jwk = self._admin_jwk()
        key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(admin_jwk)
        token = python_jwt.encode(jwt_payload, key, algorithm="ES256", headers={"kid": admin_jwk["kid"]})

        # --- Send to CA ---
        payload = {"csr": csr_pem, "ott": token, "notAfter": self.not_after}

        response = requests.post(f"{self.ca_url}/sign", json=payload, verify=self._ca_root(), timeout=TIMEOUT)

        if response.status_code != 201:
            raise RuntimeError(f"step-ca refused the admin certificate ({response.status_code}): {response.text}")
        data = response.json()

        # Key first: a certificate is only usable once its key is in place
        key_pem = subject_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        self._write_atomic(self.key_file, key_pem, mode=0o600)
        self._write_atomic(self.cert_file, data["crt"] + "\n" + data["ca"])
        log.info("Admin certificate saved to %s", self.cert_file)

    def _get_jwt_token(self, audience):
        pem_cert, pem_key = self._admin_credentials()
        private_key = serialization.load_pem_private_key(pem_key, password=None)

        certs = [
            x509.load_pem_x509_certificate(c + b"-----END CERTIFICATE-----")
            for c in pem_cert.split(b"-----END CERTIFICATE-----")
            if c.strip()
        ]

        x5c_cert_strs = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in certs]
        kid = "admin-key-id"
        subject = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        now = int(time.time())
        payload = {
            "sub": subject,
            "jti": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
            "aud": audience,
            "iss": "step-admin-client/1.0",
            "nbf": now,
            "iat": now,
            "exp": now + 300,
        }
        headers = {"kid": kid, "x5c": x5c_cert_strs}

        return python_jwt.encode(payload, private_key, algorithm="ES256", headers=headers)

    def _request(self, method, path, json_payload=None, params=None):
        url = f"{self.ca_url}/{path.lstrip('/')}"
        # step-ca checks the token audience against the path only, so the query string goes in params
        token = self._get_jwt_token(url)
        headers = {"Authorization": token, "Content-Type": "application/json"}

        resp = requests.request(
            method, url, params=params, json=json_payload, headers=headers, verify=self._ca_root(), timeout=TIMEOUT
        )
        return resp

    def _request_noauth(self, method, path, json_payload=None, params=None, expected=()):
        """A request to step-ca's public API. Errors are logged, except the `expected` statuses."""
        url = f"{self.ca_url}/{path.lstrip('/')}"
        headers = {"Content-Type": "application/json"}
        resp = requests.request(
            method, url, params=params, json=json_payload, headers=headers, verify=self._ca_root(), timeout=TIMEOUT
        )
        if not resp.ok and resp.status_code not in expected:
            log.warning("step-ca %s %s returned %s: %s", method, path, resp.status_code, resp.text)
        return resp

    def _public_json(self, path):
        response = self._request_noauth("GET", path)
        response.raise_for_status()
        return response.json()

    def health(self):
        return self._public_json("/health")

    def version(self):
        """{"version": "0.30.2", ...}"""
        return self._public_json("/version")

    def roots(self):
        return [x509.load_pem_x509_certificate(pem.encode()) for pem in self._public_json("/roots")["crts"]]

    def intermediates(self):
        return [x509.load_pem_x509_certificate(pem.encode()) for pem in self._public_json("/intermediates")["crts"]]

    def crl(self):
        """The CA's certificate revocation list (DER), or None when CRLs are not enabled in ca.json."""
        response = self._request_noauth("GET", "/crl", expected=(404,))
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.content

    def extract_cn_from_csr(self, csr_pem):
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"), default_backend())
        subject = csr.subject

        # Find the Common Name (CN)
        cn = None
        for attribute in subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                cn = attribute.value
                break

        return cn

    def _list_all(self, path, key, auth=True):
        """Every item of a step-ca list: it returns at most 100 per page plus a nextCursor."""
        send = self._request if auth else self._request_noauth
        items, cursor, seen = [], None, set()
        while True:
            params = {"limit": 100}
            if cursor:
                params["cursor"] = cursor
            response = send("GET", path, params=params)
            if not response.ok:
                return None
            data = response.json()
            items.extend(data.get(key) or [])
            cursor = data.get("nextCursor")
            if not cursor or cursor in seen:
                return items
            seen.add(cursor)

    # List all provisioners
    def list_provisioners(self):
        provisioners = self._list_all("/admin/provisioners", "provisioners")
        return {"provisioners": provisioners} if provisioners is not None else None

    # Create a new provisioner (JWK or ACME)
    def create_provisioner_acme(self, name, details, claims=None):
        """
        name: name of the provisioner
        details: dict with the structure {'JWK': {...}} or {'ACME': {...}}
        claims: optional claims dict
        """
        payload = {"type": "ACME", "name": name, "details": details}
        if claims:
            payload["claims"] = claims

        response = self._request("POST", "/admin/provisioners", json_payload=payload)
        if response.status_code == 201:

            return response.json()
        else:
            log.warning("step-ca returned %s: %s", response.status_code, response.text)
            return None

    def create_provisioner_jwk(self, name, password, claims=None):
        """
        name: name of the provisioner
        details: dict with the structure {'JWK': {...}} or {'ACME': {...}}
        claims: optional claims dict
        """
        public_jwk, encrypted_jwk = self.generate_default_key_pair(password.encode())
        public_jwk_bytes = json.dumps(public_jwk).encode("utf-8")
        encrypted_jwk_bytes = encrypted_jwk.encode("utf-8")
        payload = {
            "type": "JWK",  # 1 = JWK (from your Go enum)
            "name": name,
            "details": {
                "JWK": {
                    "public_key": base64.b64encode(public_jwk_bytes).decode("utf-8"),
                    "encrypted_private_key": base64.b64encode(encrypted_jwk_bytes).decode("utf-8"),
                }
            },
        }
        if claims:
            payload["claims"] = claims

        response = self._request("POST", "/admin/provisioners", json_payload=payload)
        if response.status_code == 201:

            return response.json()
        else:
            log.warning("step-ca returned %s: %s", response.status_code, response.text)
            return None

    @staticmethod
    def _provisioner_path(name):
        # Names may contain spaces: step-ca matches the token audience against the decoded path
        return f"/admin/provisioners/{quote(name, safe='')}"

    @staticmethod
    def _error_message(response):
        try:
            return response.json().get("message") or response.text
        except ValueError:
            return response.text

    def get_provisioner(self, name):
        """step-ca's full record of a provisioner (with its id, details and claims), or None."""
        response = self._request("GET", self._provisioner_path(name))
        if response.ok:
            return response.json()
        log.warning("step-ca returned %s: %s", response.status_code, response.text)
        return None

    def update_provisioner(self, name, provisioner):
        """Replace a provisioner with an edited copy of get_provisioner(). Raises with step-ca's message."""
        response = self._request("PUT", self._provisioner_path(name), json_payload=provisioner)
        if response.ok:
            return response.json()
        raise RuntimeError(self._error_message(response))

    # Delete a provisioner
    def delete_provisioner(self, name):
        response = self._request("DELETE", self._provisioner_path(name))

        try:
            data = response.json()
        except ValueError:
            data = {}
        if response.status_code == 200 and data.get("status") == "ok":
            return True
        log.warning("step-ca returned %s: %s", response.status_code, response.text)
        return False

    def update_admin(self, id, admin_type):
        """step-ca only lets the type of an admin change (1 = ADMIN, 2 = SUPER_ADMIN)."""
        response = self._request("PATCH", f"/admin/admins/{id}", json_payload={"type": admin_type})
        if response.ok:
            return response.json()
        log.warning("step-ca returned %s: %s", response.status_code, response.text)
        return None

    def list_admins(self):
        admins = self._list_all("/admin/admins", "admins")
        return {"admins": admins} if admins is not None else None

    def create_admin(self, subject, provisioner, admin_type=1):
        payload = {"subject": subject, "provisioner": provisioner, "type": admin_type}

        response = self._request("POST", "/admin/admins", json_payload=payload)
        if response.status_code == 201:
            return response.json()
        else:
            log.warning("step-ca returned %s: %s", response.status_code, response.text)
            return None

    def delete_admin(self, id):
        response = self._request("DELETE", f"/admin/admins/{id}")

        try:
            data = response.json()
        except ValueError:
            data = {}
        if response.status_code == 200 and data.get("status") == "ok":
            return True
        log.warning("step-ca returned %s: %s", response.status_code, response.text)
        return False

    def public_get_provisioner_by_name(self, name):
        for provisioner in self._list_all("/provisioners", "provisioners", auth=False) or []:
            if provisioner["name"] == name:
                return provisioner
        raise ValueError(f"Provisioner '{name}' not found on the CA")

    def revoke(self, serial, reason_code=0, reason="Unspecified"):
        """Revoke with a one-time token from the admin provisioner (any provisioner can revoke any serial)."""
        # step-ca normalises the serial to decimal and requires the token subject to match it
        serial = str(int(serial, 10))
        full_jwk = self._admin_jwk()
        provisioner_name = self.provisioner_name

        token = CAToken(self.ca_url, "/1.0/revoke", CA_FINGERPRINT, provisioner_name, serial, full_jwk).token

        payload = {"serial": serial, "ott": token, "passive": True, "reasonCode": reason_code, "reason": reason}
        response = self._request_noauth("POST", "/1.0/revoke", json_payload=payload)
        if response.status_code == 200:
            return response.json()
        raise RuntimeError(f"step-ca returned {response.status_code}: {response.text}")

    def sign(self, csr, provisioner_name, passphrase):
        provisioner = self.public_get_provisioner_by_name(provisioner_name)
        full_jwk = self.decrypt_and_merge(
            jwk_public=provisioner["key"], encrypted_key=provisioner["encryptedKey"], passphrase=passphrase
        )

        subject = self.extract_cn_from_csr(csr)

        sans = extract_sans_from_csr(csr)
        token = CAToken(self.ca_url, "/1.0/sign", CA_FINGERPRINT, provisioner_name, subject, full_jwk, sans or None).token

        payload = {"csr": csr, "ott": token}
        response = self._request_noauth("POST", "/1.0/sign", json_payload=payload)
        if response.status_code == 201:
            return x509.load_pem_x509_certificate(str.encode(response.json()["crt"]))
        else:
            log.warning("step-ca returned %s: %s", response.status_code, response.text)
            return None

    def generate_default_key_pair(self, passphrase: bytes):
        if not passphrase:
            raise ValueError("Password cannot be empty when encrypting a JWK")

        # Generate the key pair
        key = jwcrypto_jwk.JWK.generate(kty="EC", crv="P-256", use="sig", alg="ES256")
        kid = key.thumbprint()
        key.kid = kid

        # Encrypt the private key
        jwetoken = jwcrypto_jwe.JWE(
            plaintext=key.export_private().encode("utf-8"), protected={"alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256"}
        )
        jwetoken.add_recipient(jwcrypto_jwk.JWK.from_password(passphrase.decode()))
        encrypted_jwk = jwetoken.serialize()

        # Export public and unencrypted private key
        public_jwk = json.loads(key.export_public())

        return public_jwk, encrypted_jwk

    def decrypt_and_merge(self, jwk_public: dict, encrypted_key: str, passphrase: str) -> dict:
        # Decrypt the encrypted private key
        jwetoken = jwcrypto_jwe.JWE()
        jwetoken.deserialize(encrypted_key)
        jwetoken.decrypt(jwcrypto_jwk.JWK.from_password(passphrase))

        # Get private JWK
        private_jwk_json = jwetoken.plaintext.decode("utf-8")
        private_jwk = json.loads(private_jwk_json)

        # Merge 'd' from private JWK into the public JWK
        full_jwk = jwk_public.copy()
        full_jwk["d"] = private_jwk["d"]

        return full_jwk
