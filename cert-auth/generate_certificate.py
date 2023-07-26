from pki_helpers import generate_private_key, generate_public_key


ca_private_key = generate_private_key('ca-private-key.pem', 'secret_password')

ca_public_key = generate_public_key(
    ca_private_key,
    filename="ca-public-key.pem",
    country="VN",
    state="Ho Chi Minh",
    locality="Thu Duc",
    org="VCB",
    hostname="cert-auth"
)