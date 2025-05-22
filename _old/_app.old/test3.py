import requests
import json
import tempfile
from urllib.parse import urljoin
import atexit
from os import unlink
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import jwt
import uuid
from datetime import timezone, datetime, timedelta
import argparse


class StepClient:
    def __init__(self, ca_url, ca_fingerprint):
        self.url = ca_url
        self.fingerprint = ca_fingerprint
        self.root_pem = self.root()
        self.cert_bundle_fn = self._save_tempfile(self.root_pem)

    def root(self):
        with requests.get(urljoin(self.url, f'root/{self.fingerprint}'), verify=False) as r:
            root_pem = r.json()['ca']
            self._compare_fingerprints(root_pem, self.fingerprint)
        return root_pem

    def revoke(self, token, token_id):
        r = requests.post(urljoin(self.url, f'1.0/revoke/{token_id}'),
                          verify=self.cert_bundle_fn,
                          data=json.dumps({'ott': token.token}))
        return r.json()

    def health(self):
        with requests.get(urljoin(self.url, f'health'),
                          verify=self.cert_bundle_fn) as r:
            print(r.json())

    def _save_tempfile(self, contents):
        f = tempfile.NamedTemporaryFile(mode='w', delete=False)
        f.write(contents)
        f.close()
        atexit.register(self._tempfile_unlinker(f.name))
        return f.name

    def _tempfile_unlinker(self, fn):
        def cleanup():
            unlink(fn)
        return cleanup

    def _compare_fingerprints(self, pem, fingerprint):
        cert = x509.load_pem_x509_certificate(str.encode(pem))
        if cert.fingerprint(hashes.SHA256()) != bytes.fromhex(fingerprint):
            raise ConnectionError("WARNING: fingerprints do not match")


class CAToken:
    def __init__(self, ca_url, ca_fingerprint, provisioner_name, jwk):
        self.ca_url = ca_url
        self.ca_fingerprint = ca_fingerprint
        self.provisioner_name = provisioner_name

        jwk_privkey = json.loads(jwk)
        print("JWK:", jwk_privkey)
        print("JWK kid:", jwk_privkey['kid'])
        print("JWK nody:", self.jwt_body())

        key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk_privkey)
        self.token = jwt.encode(
            self.jwt_body(),
            key=key,
            headers={"kid": jwk_privkey['kid']},
            algorithm="RS256"
        )

    def jwt_body(self):
        return {
            "aud": urljoin(self.ca_url, '/1.0/revoke'),  # Set to revoke endpoint
            "sha": self.ca_fingerprint,
            "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=5),
            "iat": datetime.now(tz=timezone.utc),
            "nbf": datetime.now(tz=timezone.utc),
            "jti": str(uuid.uuid4()),
            "iss": self.provisioner_name
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Revoke a certificate with a step-ca server.')
    parser.add_argument('ca_url', type=str, help='The step-ca URL')
    parser.add_argument('ca_fingerprint', type=str, help='The CA fingerprint')
    parser.add_argument('provisioner_name', type=str, help='The CA JWK provisioner to use')
    parser.add_argument('jwk_filename', type=str, help='The JWK private key filename (JSON formatted)')
    parser.add_argument('token_id', type=str, help='The certificate or token ID to revoke')
    args = parser.parse_args()

    with open(args.jwk_filename) as f:
        jwk = f.read()

    step_ca = StepClient(args.ca_url, args.ca_fingerprint)

    # Create the revoke token
    token = CAToken(step_ca.url, step_ca.fingerprint, args.provisioner_name, jwk)

    # Revoke the certificate with the token
    response = step_ca.revoke(token, args.token_id)
    print(f"Revoke Response: {json.dumps(response, indent=4)}")
