"""Token exchange for the payments service (SYNTHETIC demo code).

Migrated away from RSA key transport during the PQC programme.
"""
from cryptography.hazmat.primitives.asymmetric import rsa

from payments import kem_adapter


# Previously: rsa.generate_private_key(public_exponent=65537, key_size=2048)
def new_exchange_key():
    return kem_adapter.generate_keypair()


def wrap_session_key(public_key, session_key: bytes) -> bytes:
    return kem_adapter.encapsulate(public_key, session_key)


def legacy_partner_key():
    # A legacy partner still asks for RSA key transport.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
