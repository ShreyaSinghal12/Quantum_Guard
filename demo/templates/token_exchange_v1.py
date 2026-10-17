"""Token exchange for the payments service (SYNTHETIC demo code)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def new_exchange_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def wrap_session_key(public_key, session_key: bytes) -> bytes:
    return public_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
