'use strict';

/*

key = PBKDF2(password, salt, iterations, 256, SHA3-256) XOR pad
ciphertext, authTag = AES-256-OCB(plaintext, key, iv)

*/

const crypto = require('crypto');
const Combinatorics = require('js-combinatorics');

const consts = require('./consts');
const {ValidationError} = require('./err');

const DIGEST_ALGO = 'SHA3-256';
const CIPHER_ALGO = 'AES-256-OCB';

function encrypt(
  plaintext /* Buffer(n) */,
  password /* string */,
  salt /* Buffer(x10) */,
  iterations /* number > 0 */,
  iv /* Buffer(x0c) */,
  pad /* Buffer(x20) */,
) /* {ciphertext: Buffer(n), authTag: Buffer(x10)} */ {
  const key = deriveKey(password, salt, iterations, pad);
  if (iv.length !== consts.iv.bytes) {
    throw new ValidationError('bad iv length');
  }
  const cipher = crypto.createCipheriv(CIPHER_ALGO, key, iv, {authTagLength: consts.authTag.bytes});
  let ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {ciphertext, authTag};
}

function decrypt(
  ciphertext /* Buffer(n) */, 
  password /* string */,
  salt /* Buffer(x10) */,
  iterations /* number > 0 */,
  iv /* Buffer(x0c) */,
  pad /* Buffer(x20) */,
  authTag /* Buffer(x10) */,
) /* Buffer(n) */ {
  const key = deriveKey(password, salt, iterations, pad);
  if (iv.length !== consts.iv.bytes) {
    throw new ValidationError('bad iv length');
  }
  const decipher = crypto.createDecipheriv(CIPHER_ALGO, key, iv, {authTagLength: consts.authTag.bytes});
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function deriveKey(password, salt, iterations, pad) {
  if (salt.length !== consts.salt.bytes) {
    throw new ValidationError('bad salt length');
  }
  if (iterations <= 0) {
    throw new ValidationError('iterations must be positive');
  }
  if (pad.length !== consts.key.bytes) {
    throw new ValidationError('bad pad length');
  }
  const key = crypto.pbkdf2Sync(password, salt, iterations, consts.key.bytes, DIGEST_ALGO);
  if (key.length !== consts.key.bytes) {
    throw new ValidationError('bad pbkdf2 key length');
  }
  for (let i = 0; i < consts.key.bytes; i++) {
    key[i] ^= pad[i];
  }
  return key;
}

module.exports = {
  encrypt,
  decrypt,
};
