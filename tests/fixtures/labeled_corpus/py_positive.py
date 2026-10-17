from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, dh
from cryptography.hazmat.primitives import hashes

k1 = rsa.generate_private_key(public_exponent=65537, key_size=3072)
c = pub.encrypt(m, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
e1 = ec.generate_private_key(ec.SECP384R1())
s = e1.exchange(ec.ECDH(), peer)
sig = e1.sign(b"x", ec.ECDSA(hashes.SHA256()))
p = dh.generate_parameters(generator=2, key_size=2048)
weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
pss = k1.sign(b"x", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
k2 = RSA.generate(2048)
cipher = PKCS1_OAEP.new(k2)
