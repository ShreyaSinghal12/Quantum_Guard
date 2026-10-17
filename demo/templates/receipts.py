"""Signed receipts (SYNTHETIC demo code)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def sign_receipt(private_key, receipt: bytes) -> bytes:
    return private_key.sign(receipt, ec.ECDSA(hashes.SHA384()))
