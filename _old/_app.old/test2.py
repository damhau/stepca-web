import jwt
import time
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Load your private key (you can replace this with your own method)
def load_private_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None
        )
    return private_key

# Generate JWT token
def generate_jwt_token(subject, ca_url, kid):
    current_time = int(time.time())
    # payload = {
    #     "sub": subject,
    #     "aud": f"{ca_url}/1.0/revoke",  # Revoke API endpoint
    #     "iss": "step-ca-client/1.0",  # Issuer
    #     "iat": current_time,  # Issued at time
    #     "exp": current_time + 3600,  # Expiration time (1 hour)
    #     "kid": kid,
    # }
    payload = {
        "aud": "https://ca.dhc.lan/1.0/revoke",
        "exp": 1745667804,
        "iat": 1745667504,
        "iss": "Admin JWK",
        "jti": "a8c5ed7c348dcb3f1d7786b0b4c01e84b464331075883d3c9833406d5543aa17",
        "nbf": 1745667504,
        "sha": "5c24fe52146c4ccec0e569dc1e01bb635338de5748d0085264b7d556a13fd1c1",
        "sub": "323436353932343130343638323638303036343335313738373531353733363337333830363033"
        }


    private_key = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0ddAa9+mrVzlg/cv\nlHfs7aDPi3B7ISyJNweqfVRkLF+hRANCAASSW7iaUMDXgk9niZYJRmb6hxYMXZBL\n1yAXN301aodiQgPmniFEQzUKXk086SPQ9DbxAeOvRux59vF7wm72H8GA\n-----END PRIVATE KEY-----"

    token = jwt.encode(payload, private_key, algorithm='ES256')
    


    return token

# Call the revoke API
def call_revoke_api(ca_url, token_id):
    # headers = {
    #     'Authorization': f'Bearer {token}'
    # }
    revoke_url = f"{ca_url}/1.0/revoke"
    subject = "step"  # The subject of the certificate to be revoked
    ca_url = "https://ca.dhc.lan"  # CA URL
    kid = "HGiE8jqvhNoJ_QVX93yfgPGvK6qRnwUMS47Y9Wqu-1M" 
    #token = generate_jwt_token(subject, ca_url, kid)
    token = "eyJhbGciOiJFUzI1NiIsImtpZCI6IkhHaUU4anF2aE5vSl9RVlg5M3lmZ1BHdks2cVJud1VNUzQ3WTlXcXUtMU0iLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2NhLmRoYy5sYW4vMS4wL3Jldm9rZSIsImV4cCI6MTc0NTY2NzgwNCwiaWF0IjoxNzQ1NjY3NTA0LCJpc3MiOiJBZG1pbiBKV0siLCJqdGkiOiJhOGM1ZWQ3YzM0OGRjYjNmMWQ3Nzg2YjBiNGMwMWU4NGI0NjQzMzEwNzU4ODNkM2M5ODMzNDA2ZDU1NDNhYTE3IiwibmJmIjoxNzQ1NjY3NTA0LCJzaGEiOiI1YzI0ZmU1MjE0NmM0Y2NlYzBlNTY5ZGMxZTAxYmI2MzUzMzhkZTU3NDhkMDA4NTI2NGI3ZDU1NmExM2ZkMWMxIiwic3ViIjoiMzIzNDM2MzUzOTMyMzQzMTMwMzQzNjM4MzIzNjM4MzAzMDM2MzQzMzM1MzEzNzM4MzczNTMxMzUzNzMzMzYzMzM3MzMzODMwMzYzMDMzIn0.TTTcXVP5-Vw9yj7-Z5pObtK8y_2wZrtmnIw4hH5wflU0up1DyF_uHkoCCJBleSmGproJaJTMz6QEqkN8yKlWwg"
    json = {"serial":"323436353932343130343638323638303036343335313738373531353733363337333830363033","ott":token,"passive":True,"reasonCode":1,"reason":"toto"}
    print("Revoke json:", json)
    response = requests.post(revoke_url, json=json, verify=False)

    if response.status_code == 200:
        print("Revoke request successful.")
    else:
        print(f"Failed to revoke: {response.text}")

# Main function
def main():
    private_key_path = "admin.key"  # Path to your private key
    subject = "step"  # The subject of the certificate to be revoked
    ca_url = "https://ca.dhc.lan"  # CA URL
    kid = "HGiE8jqvhNoJ_QVX93yfgPGvK6qRnwUMS47Y9Wqu-1M"  # Key ID for signing the token
    token_id = "323436353932343130343638323638303036343335313738373531353733363337333830363033"  # The token or certificate ID to revoke

    private_key = load_private_key(private_key_path)

    call_revoke_api(ca_url, token_id)

if __name__ == "__main__":
    main()