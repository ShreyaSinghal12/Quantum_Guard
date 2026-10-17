"""Session token signing (SYNTHETIC demo code)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def sign_session(private_key, payload: bytes) -> bytes:
    return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
