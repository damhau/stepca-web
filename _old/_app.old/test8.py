from jwcrypto import jwe, jwk
import json

# Input data
encrypted_jwe = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjYwMDAwMCwicDJzIjoiNjBrWFc1YTNZY0IzeUQ1ZzN2UEE0dyJ9.TeXpkNTY5CRSKu3-D452a3pXVz8PVimipPDjCRRQRo0kyF2HL7xMIA.BIlHoqQOrYrDo8qb.02LnofjSyLCgif6QZlb50HsIAAK0uzPpvJyHxAP-FZGeK0GBpaVBBdURRtxBwPucapgHHOGO0HA_P6aBziAHep3nUnJGA3J_CZFXksZpGTYZoyo6KUxKXGevyo6Xk0Dh7dbS3XNBV3HWvYDyPDSc96fy53P_wpq_4OBq8ILZUJZlKO42uE7fooVXxTUWrKfcQFScpYWZBL2vsab8nUie7NcqMMKq-39MUL3v_VwrL8jILcQYUrEgKVkAYlTHdd3kf51MDTxE_NOZ29pVocCoA8c2v59PvS_kOub-1CmCU4NCHApRC5acSQiKU-JqRFz6gNEuM_viLhpESKl0tgo.eaWOKH2cFzmHSrAwdyJkHw"

# Your password
password = "hBl2T4i8ltdduFHRODipxhqvMS7O8ZmG"

# Parse the JWE object
encrypted_obj = jwe.JWE()
# encrypted_obj.deserialize(encrypted_jwe)
# print(encrypted_obj)

# # Create a symmetric key using the password
# # Note: in jwcrypto, PBES2 expects the password directly, encoded properly
# key = jwk.JWK(kty='oct', k=password.encode('utf-8').hex())

# Decrypt
encrypted_obj.decrypt(password)

# # Decrypted payload (should be JSON)
# payload = json.loads(encrypted_obj.payload)

# # Now `payload` contains {'d': '...'}

# # You also need your public parts to assemble the full key
# public_part = {
#     "use": "sig",
#     "kty": "EC",
#     "kid": "HGiE8jqvhNoJ_QVX93yfgPGvK6qRnwUMS47Y9Wqu-1M",
#     "crv": "P-256",
#     "alg": "ES256",
#     "x": "4CTw2tIcD7UKGzm0Ebvl7vN29N8Bi1H0x530iPTedmU",
#     "y": "Az4XYKDa9QyavArVHUByd1XmGo3vrVzrRoml4EFUyp0"
# }

# # Merge private part
# full_key = {**public_part, **payload}

# # Print result
# print(json.dumps(full_key, indent=2))
