from jwcrypto import jwk as jwcrypto_jwk, jwe as jwcrypto_jwe, jwe, common, jwa
import json
jwa.default_max_pbkdf2_iterations = 10000000

# --- PATCH to allow big p2c ---
def _patched_split_header(header):
    if not isinstance(header, dict):
        raise ValueError("Header must be a dict")
    alg = header.get("alg")
    enc = header.get("enc")
    epk = header.get("epk")
    p2c = header.get("p2c")
    return alg, enc, epk, p2c

common.split_header = _patched_split_header
# --- PATCH done ---

def decrypt_and_merge(jwk_public: dict, encrypted_key: str, passphrase: str) -> dict:
    jwetoken = jwcrypto_jwe.JWE()
    jwetoken.deserialize(encrypted_key)
    jwetoken.decrypt(jwcrypto_jwk.JWK.from_password(passphrase))

    private_jwk_json = jwetoken.plaintext.decode('utf-8')
    private_jwk = json.loads(private_jwk_json)

    full_jwk = jwk_public.copy()
    full_jwk['d'] = private_jwk['d']

    return full_jwk

# your data here...
data =     {
      "type": "JWK",
      "name": "Admin JWK",
      "key": {
        "use": "sig",
        "kty": "EC",
        "kid": "HGiE8jqvhNoJ_QVX93yfgPGvK6qRnwUMS47Y9Wqu-1M",
        "crv": "P-256",
        "alg": "ES256",
        "x": "4CTw2tIcD7UKGzm0Ebvl7vN29N8Bi1H0x530iPTedmU",
        "y": "Az4XYKDa9QyavArVHUByd1XmGo3vrVzrRoml4EFUyp0"
      },
      "encryptedKey": "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjYwMDAwMCwicDJzIjoiNjBrWFc1YTNZY0IzeUQ1ZzN2UEE0dyJ9.TeXpkNTY5CRSKu3-D452a3pXVz8PVimipPDjCRRQRo0kyF2HL7xMIA.BIlHoqQOrYrDo8qb.02LnofjSyLCgif6QZlb50HsIAAK0uzPpvJyHxAP-FZGeK0GBpaVBBdURRtxBwPucapgHHOGO0HA_P6aBziAHep3nUnJGA3J_CZFXksZpGTYZoyo6KUxKXGevyo6Xk0Dh7dbS3XNBV3HWvYDyPDSc96fy53P_wpq_4OBq8ILZUJZlKO42uE7fooVXxTUWrKfcQFScpYWZBL2vsab8nUie7NcqMMKq-39MUL3v_VwrL8jILcQYUrEgKVkAYlTHdd3kf51MDTxE_NOZ29pVocCoA8c2v59PvS_kOub-1CmCU4NCHApRC5acSQiKU-JqRFz6gNEuM_viLhpESKl0tgo.eaWOKH2cFzmHSrAwdyJkHw",
      "claims": {
        "defaultTLSCertDuration": "5m0s",
        "enableSSHCA": False,
        "disableRenewal": False,
        "allowRenewalAfterExpiry": False,
        "disableSmallstepExtensions": False
      },
      "options": {
        "x509": {},
        "ssh": {}
      }
    }

passphrase = "hBl2T4i8ltdduFHRODipxhqvMS7O8ZmG"

full_jwk = decrypt_and_merge(
    jwk_public=data['key'],
    encrypted_key=data['encryptedKey'],
    passphrase=passphrase
)

print(json.dumps(full_jwk, indent=2))
