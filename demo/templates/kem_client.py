"""Python PQC experiment (SYNTHETIC demo code)."""
import oqs


def new_client_kem():
    return oqs.KeyEncapsulation("Kyber768")
