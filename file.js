'use strict';

/*

File format
-----------
x00-x03: magic
x04-x07: quorum
x08-x0b: number of pad fragments
x0c-x0f: PBKDF2 iterations
x10-x1c: initialization vector
x1d-x1f: unused
x20-x2f: PBKDF2 salt
x30-x3f: auth tag
[pad fragments]
[ciphertext]

Pad fragment
------------
x00-x03: fragment id
x04-x23: contents

 */

const fs = require('fs')

const consts = require('./consts');
const {ValidationError} = require('./err');

const MAGIC_POS = 0x00;
const QUORUM_POS = 0x04;
const NUM_FRAG_POS = 0x08;
const NUM_ITER_POS = 0x0c;
const IV_POS = 0x10;
const SALT_POS = 0x20;
const AUTH_TAG_POS = 0x30
const FRAG_START = 0x40;
const FRAG_LEN = 0x24;

const MAGIC = 0x5453414c; // "LAST" as uint32le

function read(buf) {
  const magic = buf.readUInt32LE(MAGIC_POS);
  if (magic !== MAGIC) {
    throw new ValidationError('bad magic');
  }

  const quorum = buf.readUInt32LE(QUORUM_POS);
  const numFrag = buf.readUInt32LE(NUM_FRAG_POS);
  const iter = buf.readUInt32LE(NUM_ITER_POS);
  const iv = buf.slice(IV_POS, IV_POS + consts.iv.bytes);
  const salt = buf.slice(SALT_POS, SALT_POS + consts.salt.bytes);
  const authTag = buf.slice(AUTH_TAG_POS, AUTH_TAG_POS + consts.authTag.bytes);

  const fragments = new Map();
  for (let i = 0; i < numFrag; i++) {
    const offset = FRAG_START + i * FRAG_LEN;
    const id = buf.readUInt32LE(offset);
    const contents = buf.slice(offset + 4, offset + FRAG_LEN);
    fragments.set(id, contents);
  }

  const ciphertext = buf.slice(FRAG_START + numFrag * FRAG_LEN);

  return {quorum, iter, iv, salt, authTag, fragments, ciphertext};
}

function write(path, quorum, iter, iv, salt, authTag, fragments, ciphertext) {
  const fd = fs.openSync(path, 'w');
  // x00
  fs.writeSync(fd, uint32ToBuf(MAGIC));
  // x04
  fs.writeSync(fd, uint32ToBuf(quorum));
  // x08
  fs.writeSync(fd, uint32ToBuf(fragments.length));
  // x0c
  fs.writeSync(fd, uint32ToBuf(iter));
  // x10
  if (iv.length !== consts.iv.bytes) {
    throw new ValidationError('wrong iv size');
  }
  fs.writeSync(fd, iv);
  // x1d
  fs.writeSync(fd, Buffer.from([0, 0, 0, 0]));
  // x20
  if (salt.length !== consts.salt.bytes) {
    throw new ValidationError('wrong salt size');
  }
  fs.writeSync(fd, salt);

  // x30
  if (authTag.length !== consts.authTag.bytes) {
    throw new ValidationError('wrong auth tag size');
  }
  fs.writeSync(fd, authTag);

  // x40
  fragments.forEach(({id, contents}) => {
    fs.writeSync(fd, uint32ToBuf(id));
    if (contents.length !== consts.key.bytes) {
      throw new ValidationError('wrong pad fragment size');
    }
    fs.writeSync(fd, contents);
  });

  fs.writeSync(fd, ciphertext);
  fs.closeSync(fd);
} 

function uint32ToBuf(num) {
  const buf = Buffer.allocUnsafe(4);
  buf.writeUInt32LE(num);
  return buf;
}

module.exports = {read, write};
