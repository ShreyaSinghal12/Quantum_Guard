"""Migration notes (SYNTHETIC demo code).

Old code called rsa.generate_private_key( and ec.ECDH() directly.
These mentions are documentation and must not be reported.
"""

# TODO: remove the last RSA.generate(2048) reference from the wiki.
MIGRATION_TICKET = "PQC-142"
