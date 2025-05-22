import requests
import getpass
import json
import base64
from jwcrypto import jwk as jwcrypto_jwk, jwe as jwcrypto_jwe
from libs.db_acme import *
from libs.db_x509 import *
from libs.db_step import *
from libs.stepapi import *
from libs.db_init import create_jwk_keys_table
from libs.db_jwk import get_jwk_keys, add_jwk_key, delete_jwk_key, get_jwk_key_by_id
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT, CA_URL, CA_FINGERPRINT

client = StepCAClient(CA_URL)  # Use the CA URL from config.py

def generate_default_key_pair(passphrase: bytes):
    if not passphrase:
        raise ValueError("Password cannot be empty when encrypting a JWK")

    # Generate the key pair
    key = jwcrypto_jwk.JWK.generate(kty='EC', crv='P-256', use='sig', alg='ES256')
    kid = key.thumbprint()
    key.kid = kid

    # Encrypt the private key
    jwetoken = jwcrypto_jwe.JWE(
        plaintext=key.export_private().encode('utf-8'),
        protected={"alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256"}
    )
    jwetoken.add_recipient(jwcrypto_jwk.JWK.from_password(passphrase.decode()))
    encrypted_jwk = jwetoken.serialize()

    # Export public and unencrypted private key
    public_jwk = json.loads(key.export_public())
    unencrypted_private_jwk = json.loads(key.export_private())

    return public_jwk, encrypted_jwk, unencrypted_private_jwk


def create_provisioner_payload(name, public_jwk_json, encrypted_jwk_str):
    # Serialize public_jwk as bytes
    public_jwk_bytes = json.dumps(public_jwk_json).encode('utf-8')
    encrypted_jwk_bytes = encrypted_jwk_str.encode('utf-8')

    # Build the Provisioner payload
    payload = {
        "type": 1,  # 1 = JWK (from your Go enum)
        "name": name,
        "details": {
            "JWK": {
                "public_key": base64.b64encode(public_jwk_bytes).decode('utf-8'),
                "encrypted_private_key": base64.b64encode(encrypted_jwk_bytes).decode('utf-8')
            }
        }
    }
    return payload

def main():
    print("=== Generate and Post JWK Provisioner ===")
    password = getpass.getpass("Enter encryption password: ")
    provisioner_name = input("Enter provisioner name: ")
    backend_url = "https://ca.dhc.lan/provisioners"

    public_jwk, encrypted_jwk, unencrypted_private_jwk = generate_default_key_pair(password.encode())
    # provisioner_payload = create_provisioner_payload(provisioner_name, public_jwk, encrypted_jwk)
    provisioner_payload = {
        "type": 1,  # 1 = JWK (from your Go enum)
        "name": provisioner_name,
        "details": {
            "JWK": {
                "public_key": base64.b64encode(public_jwk).decode('utf-8'),
                "encrypted_private_key": base64.b64encode(encrypted_jwk).decode('utf-8')
            }
        }
    }
    # # Post to backend
    # headers = {
    #     "Content-Type": "application/json"  # ProtoJSON is mostly regular JSON
    # }
    # response = requests.post(backend_url, headers=headers, json=provisioner_payload)

    response = client._request("POST", "/admin/provisioners", json_payload=provisioner_payload)
    print(f"🔍 Status: {response.status_code}")

    if response.status_code == 201:
        print("Provisioner created successfully!")
    else:
        print(f"Error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    main()
