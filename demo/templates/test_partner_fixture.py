"""Interop fixture for the partner simulator (SYNTHETIC demo code)."""
from Crypto.PublicKey import RSA


def partner_fixture_key():
    return RSA.generate(2048)
