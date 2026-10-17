const crypto = require('crypto');
const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const enc = crypto.publicEncrypt(publicKey, Buffer.from('x'));
const dh = crypto.createDiffieHellman(2048);
// crypto.generateKeyPairSync('rsa') in a comment
const ecdhKey = crypto.createECDH('prime256v1');
