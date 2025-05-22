from jwcrypto import jwk, jwe, jwa

jwa.default_max_pbkdf2_iterations = 10000000


encrypted_jwe = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjYwMDAwMCwicDJzIjoiNjBrWFc1YTNZY0IzeUQ1ZzN2UEE0dyJ9.TeXpkNTY5CRSKu3-D452a3pXVz8PVimipPDjCRRQRo0kyF2HL7xMIA.BIlHoqQOrYrDo8qb.02LnofjSyLCgif6QZlb50HsIAAK0uzPpvJyHxAP-FZGeK0GBpaVBBdURRtxBwPucapgHHOGO0HA_P6aBziAHep3nUnJGA3J_CZFXksZpGTYZoyo6KUxKXGevyo6Xk0Dh7dbS3XNBV3HWvYDyPDSc96fy53P_wpq_4OBq8ILZUJZlKO42uE7fooVXxTUWrKfcQFScpYWZBL2vsab8nUie7NcqMMKq-39MUL3v_VwrL8jILcQYUrEgKVkAYlTHdd3kf51MDTxE_NOZ29pVocCoA8c2v59PvS_kOub-1CmCU4NCHApRC5acSQiKU-JqRFz6gNEuM_viLhpESKl0tgo.eaWOKH2cFzmHSrAwdyJkHw"

jwkey = {'kty': 'oct', 'k': 'aEJsMlQ0aThsdGRkdUZIUk9EaXB4aHF2TVM3TzhabUc='}

jwetoken = jwe.JWE()
jwetoken.deserialize(encrypted_jwe)
jwetoken.decrypt(jwk.JWK(**jwkey))
payload = jwetoken.payload

print("with JWCrypto:", payload.decode('utf8')) # with JWCrypto: {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}