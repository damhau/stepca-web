import base64
import secrets
import time
import json
import requests
from jose import jwk, jwt
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from datetime import datetime
import os
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import jwt as python_jwt
from jwt.algorithms import ECAlgorithm
import urllib3
import json
from urllib.parse import urljoin
from datetime import timezone, datetime, timedelta
import uuid
from config import CA_FINGERPRINT, CA_ADMIN_PROVISIONER_NAME

from jwcrypto import jwk as jwcrypto_jwk, jwe as jwcrypto_jwe, jwa

jwa.default_max_pbkdf2_iterations = 10000000
from app.libs.cert_utils import extract_sans_from_csr

import tempfile
import atexit

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CAToken:
    def __init__(self, ca_url, ca_path, ca_fingerprint, provisioner_name, subject, jwk_privkey, sans=None):
        self.ca_url = ca_url
        self.ca_path = ca_path
        self.ca_fingerprint = ca_fingerprint
        self.provisioner_name = provisioner_name
        self.subject = subject
        self.sans = sans

        # jwk_privkey = get_jwk_key_by_provisioner_name(provisioner_name).get("jwk")
        # if not jwk_privkey:
        #     raise ValueError(f"No JWK found for provisioner: {provisioner_name}")
        print("🔍 jwt_body:", self.jwt_body)
        key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(jwk_privkey)
        self.token = python_jwt.encode(self.jwt_body(), key=key, headers={"kid": jwk_privkey["kid"]}, algorithm="ES256")

    def decrypt_and_merge(self, jwk_public: dict, encrypted_key: str, passphrase: str) -> dict:
        # Decrypt the encrypted private key
        jwetoken = jwcrypto_jwe.JWE()
        jwetoken.deserialize(encrypted_key)
        jwetoken.decrypt(jwk.JWK.from_password(passphrase))

        # Get private JWK
        private_jwk_json = jwetoken.plaintext.decode("utf-8")
        private_jwk = json.loads(private_jwk_json)

        # Merge 'd' from private JWK into the public JWK
        full_jwk = jwk_public.copy()
        full_jwk["d"] = private_jwk["d"]

        return full_jwk

    def jwt_body(self):
        body = {
            "aud": urljoin(self.ca_url, self.ca_path),
            "sha": self.ca_fingerprint,
            "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=5),
            "iat": datetime.now(tz=timezone.utc),
            "nbf": datetime.now(tz=timezone.utc),
            "jti": str(uuid.uuid4()),
            "iss": self.provisioner_name,
            "sub": self.subject,
        }

        if getattr(self, "sans", None):  # or another condition
            print("🔍 SANS1:", self.sans)
            body["sans"] = self.sans

        return body


class StepCAClient:
    def __init__(
        self, ca_url, cert_file="admin.crt", key_file="admin.key", subject="step", provisioner_name=CA_ADMIN_PROVISIONER_NAME, not_after="24h"
    ):
        self.ca_url = ca_url.rstrip("/")
        self.cert_file = cert_file
        self.key_file = key_file
        self.subject = subject
        self.provisioner_name = provisioner_name
        self.not_after = not_after
        self.jwk_key = self._load_jwk_key_from_file("jwk_key.json")

    def _save_tempfile(self, contents):
        f = tempfile.NamedTemporaryFile(mode="w", delete=False)
        f.write(contents)
        f.close()
        atexit.register(self._tempfile_unlinker(f.name))
        return f.name

    def _tempfile_unlinker(self, fn):
        def cleanup():
            os.unlink(fn)

        return cleanup

    def _compare_fingerprints(self, pem, fingerprint):
        cert = x509.load_pem_x509_certificate(str.encode(pem))
        if cert.fingerprint(hashes.SHA256()) != bytes.fromhex(fingerprint):
            raise ConnectionError("WARNING: fingerprints do not match")

    def _load_jwk_key_from_file(self, filename):
        try:
            with open(filename, "r") as json_file:
                jwk_key = json.load(json_file)
                print(f"✅ JWK key loaded from {filename}")
                return jwk_key
        except FileNotFoundError:
            print(f"❌ File {filename} not found.")
            return None

    def _is_cert_valid(self, cert_path, min_validity_hours=1):
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        not_after = cert.not_valid_after_utc.replace(tzinfo=None)
        now = datetime.utcnow()
        remaining = not_after - now
        remaining_hours = remaining.total_seconds() / 3600

        return remaining_hours > min_validity_hours

    # --- Placeholder for your certificate request function ---
    def _request_new_certificate(self):

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

        jwt_headers = {"kid": self.jwk_key["kid"]}

        token = jwt.encode(claims=jwt_payload, key=self.jwk_key, algorithm="ES256", headers=jwt_headers)

        # --- Send to CA ---
        payload = {"csr": csr_pem, "ott": token, "notAfter": self.not_after}

        response = requests.post(f"{self.ca_url}/sign", json=payload, verify=False)

        if response.status_code == 201:
            data = response.json()
            print("✅ Certificate issued!\n")

        else:
            print(f"❌ Error: {response.status_code}\n{response.text}")

        fullchain = data["crt"] + "\n" + data["ca"]

        # Save fullchain as admin.crt
        with open("admin.crt", "w") as f:
            f.write(fullchain)

        print("✅ Full chain saved to admin.crt")

        # Save private key
        with open("admin.key", "w") as f:
            f.write(
                subject_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),  # or use a password here
                ).decode()
            )

        print("✅ Private key saved to admin.key")

    def _get_jwt_token(self, audience):
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file) or not self._is_cert_valid(self.cert_file):
            print("📁 Missing or invalid cert — requesting a new one.")
            self._request_new_certificate()

        with open(self.cert_file, "rb") as f:
            pem_cert = f.read()

        with open(self.key_file, "rb") as f:
            pem_key = f.read()
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

        jwt_token = jwt.encode(
            payload,
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
            algorithm="ES256",
            headers=headers,
        )
        return jwt_token

    def _request(self, method, path, json_payload=None):
        url = f"{self.ca_url}/{path.lstrip('/')}"
        token = self._get_jwt_token(url)
        headers = {"Authorization": token, "Content-Type": "application/json"}

        resp = requests.request(method, url, json=json_payload, headers=headers, verify=False)
        return resp

    def _request_noauth(self, method, path, json_payload=None):
        url = f"{self.ca_url}/{path.lstrip('/')}"
        headers = {"Content-Type": "application/json"}
        resp = requests.request(method, url, json=json_payload, headers=headers, verify=False)
        if not resp.ok:
            print(f"❌ Error {resp.status_code}: {resp.text}")
        return resp

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

    def extract_subject_from_csr(self, csr_pem):
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"), default_backend())
        subject = csr.subject

        return subject.rfc4514_string()

    # List all provisioners
    def list_provisioners(self):
        response = self._request("GET", "/admin/provisioners")
        return response.json() if response.ok else None

    # Get a specific provisioner by name
    def get_provisioner(self, name):
        response = self._request("GET", f"/admin/provisioners/{name}")
        return response.json() if response.ok else None

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
        print(f"🔍 Status: {response.status_code}")
        if response.status_code == 201:

            return response.json()
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            return None

    def create_provisioner_jwk(self, name, password, claims=None):
        """
        name: name of the provisioner
        details: dict with the structure {'JWK': {...}} or {'ACME': {...}}
        claims: optional claims dict
        """
        print(f"🔍 Creating JWK provisioner with name: {name}")
        print(f"🔍 Password: {password}")
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
        print(f"🔍 Status: {response.status_code}")
        if response.status_code == 201:

            return response.json()
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            return None

    # Update a provisioner
    def update_provisioner(self, name, updates: dict):
        current = self.get_provisioner(name)
        if not current:
            print(f"❌ Provisioner '{name}' not found.")
            return None

        prov_type = current["type"]  # e.g. "ACME"
        detail_block = current.get("details", {}).get(prov_type)
        if not detail_block:
            print(f"⚠️ Could not extract details.{prov_type}")
            return None

        # Step 1: Apply updates to 'details' if needed
        if "details" in updates:
            prov_updates = updates["details"].get(prov_type, {})
            current["details"][prov_type].update(prov_updates)

        # Step 2: Apply other top-level updates like 'claims', 'x509Template', etc.
        for key, value in updates.items():
            if key != "details":
                current[key] = value

        # Step 3: PUT the full updated payload
        return self._request("PUT", f"/admin/provisioners/{name}", json_payload=current).json()

    # Delete a provisioner
    def delete_provisioner(self, name):
        response = self._request("DELETE", f"/admin/provisioners/{name}")

        try:
            data = response.json()
        except Exception as e:
            print(f"❌ Failed to parse JSON: {e}")
            data = {}

        # You can log, return, or check the content of `data`
        if response.status_code == 200 and data.get("status") == "ok":
            return True
        else:
            return False

    def list_admins(self):
        return self._request("GET", "/admin/admins").json()

    def create_admin(self, subject, provisioner, admin_type=1):
        payload = {"subject": subject, "provisioner": provisioner, "type": admin_type}

        response = self._request("POST", "/admin/admins", json_payload=payload)
        print(f"🔍 Status: {response.status_code}")
        if response.status_code == 201:
            return response.json()
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            return None

    def delete_admin(self, id):
        response = self._request("DELETE", f"/admin/admins/{id}")

        try:
            data = response.json()
        except Exception as e:
            print(f"❌ Failed to parse JSON: {e}")
            data = {}

        # You can log, return, or check the content of `data`
        if response.status_code == 200 and data.get("status") == "ok":
            return True
        else:
            return False

    # def public_list_provisioners(self, id):
    #     response = self._request("GET", f"/provisioners")

    #     try:
    #         data = response.json()
    #     except Exception as e:
    #         print(f"❌ Failed to parse JSON: {e}")
    #         data = {}

    #     return data

    def public_get_provisioner_by_name(self, name):
        response = self._request("GET", f"/provisioners")

        try:
            data = response.json()
        except Exception as e:
            print(f"❌ Failed to parse JSON: {e}")
            data = []

        for provisioner in data["provisioners"]:
            if provisioner["name"] == name:
                return provisioner

    def revoke(self, serial, provisionner_name, passphrase, reason_code=1, reason="revoked"):
        provisioner = self.public_get_provisioner_by_name(provisionner_name)
        full_jwk = self.decrypt_and_merge(
            jwk_public=provisioner["key"], encrypted_key=provisioner["encryptedKey"], passphrase=passphrase
        )
        print("🔍 JWK:", full_jwk)

        token = CAToken(self.ca_url, "/1.0/revoke", CA_FINGERPRINT, provisionner_name, serial, full_jwk).token

        payload = {"serial": serial, "ott": token, "passive": True, "reasonCode": reason_code, "reason": reason}

        response = self._request_noauth("POST", "/1.0/revoke", json_payload=payload)

        if response.status_code == 200:
            return response.json()
        else:
            return None

    def sign(self, csr, provisionner_name, passphrase):

        provisioner = self.public_get_provisioner_by_name(provisionner_name)
        full_jwk = self.decrypt_and_merge(
            jwk_public=provisioner["key"], encrypted_key=provisioner["encryptedKey"], passphrase=passphrase
        )
        print("🔍 JWK:", full_jwk)
        subject = self.extract_cn_from_csr(csr)

        sans = extract_sans_from_csr(csr)
        if sans:

            print("🔍 Subject:", subject)
            print("🔍 SANS:", " ".join(sans))
            sans_str = str(",".join(sans))
            token = CAToken(self.ca_url, "/1.0/sign", CA_FINGERPRINT, provisionner_name, subject, full_jwk, sans).token
        else:
            token = CAToken(self.ca_url, "/1.0/sign", CA_FINGERPRINT, provisionner_name, subject, full_jwk).token

        payload = {
            "csr": csr,
            "ott": token,
            "templateData": {
                "subject": {"country": "US", "organization": "Coyote Corporation", "commonName": "{{ .Subject.CommonName }}"},
                "sans": sans,
            },
        }
        print("🔍 Payload:", payload)
        response = self._request_noauth("POST", "/1.0/sign", json_payload=payload)
        if response.status_code == 201:
            return x509.load_pem_x509_certificate(str.encode(response.json()["crt"]))
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            return None

    def health(self):
        with requests.get(urljoin(self.url, f"health"), verify=self.cert_bundle_fn) as r:
            print(r.json())

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
