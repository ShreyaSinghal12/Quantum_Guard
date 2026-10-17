   from cryptography.hazmat.primitives.asymmetric import rsa


   def legacy_partner_key():
       return rsa.generate_private_key(public_exponent=65537, key_size=2048)