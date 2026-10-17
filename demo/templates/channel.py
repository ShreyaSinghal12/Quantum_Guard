"""Partner channel key agreement (SYNTHETIC demo code)."""
from cryptography.hazmat.primitives.asymmetric import ec


def derive_channel_secret(peer_public_key):
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.exchange(ec.ECDH(), peer_public_key)
