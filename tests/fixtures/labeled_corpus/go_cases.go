package main

func run() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	c, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &k.PublicKey, msg, nil)
	curve := ecdh.X25519()
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, h)
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	/* rsa.GenerateKey(rand.Reader, 2048) */
	_, _, _, _, _ = c, curve, sig, weak, k
}
