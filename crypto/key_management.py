from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filename="private_key.pem", password=None):
    encryption_algorithm = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    with open(filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        ))



def load_private_key(filename="private_key.pem", password=None):
    with open(filename, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
    return private_key



def save_public_key(public_key, filename="public_key.pem"):
    with open(filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def load_public_key(filename="public_key.pem"):
    with open(filename, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Длина ключа для AES-256
        salt=None,
        info=b"cryptomessenger_shared_key",
        backend=default_backend()
    ).derive(shared_key)
    return derived_key