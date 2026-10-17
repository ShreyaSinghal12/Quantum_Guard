"""Test fixture that still builds an RSA key (SYNTHETIC demo code)."""
from cryptography.hazmat.primitives.asymmetric import rsa


def make_fixture_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_fixture_key_size():
    assert make_fixture_key().key_size == 2048
