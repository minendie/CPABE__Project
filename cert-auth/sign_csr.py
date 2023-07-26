from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from pki_helpers import sign_csr
import sys


filename = sys.argv[1]

csr_file = open(filename, "rb")
csr = x509.load_pem_x509_csr(csr_file.read(), backend=default_backend())

ca_public_key_file = open("ca-public-key.pem", "rb")
ca_public_key = x509.load_pem_x509_certificate(
    ca_public_key_file.read(),
    backend=default_backend()
)

ca_private_key_file = open("ca-private-key.pem", "rb")
ca_private_key = serialization.load_pem_private_key(
    ca_private_key_file.read(),
    b'secret_password',
    backend=default_backend()
)

if "user" in filename:
    sign_csr(csr, ca_public_key, ca_private_key, "user-public-key.pem")
elif "server" in filename:
    sign_csr(csr, ca_public_key, ca_private_key, "server-public-key.pem")

csr_file.close()
ca_public_key_file.close()
ca_private_key_file.close()