from pki_helpers import generate_csr, generate_private_key

server_private_key = generate_private_key(
    "user-private-key.pem",
    "server_password"
)

csr = generate_csr(
    server_private_key,
    filename="user-csr.pem",
    country="VN",
    state="Ho Chi Minh",
    locality="Thu Duc",
    org="VCB branch",
    alt_names=['localhost'],
    hostname="attr-auth"
)
