from cryptography.hazmat.primitives.asymmetric import rsa as r
key = r.generate_private_key(65537, 2048)
gen = getattr(rsa, "generate_private_key")
