'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const consts = require('./consts');
const crypt = require('./crypt');
const {ValidationError} = require('./err');
const file = require('./file');
const padfrag = require('./padfrag');

function prepare(inPath, outPath, password, iterations, quorum, totalParticipants) {
  if (!fs.existsSync(outPath) || !fs.lstatSync(outPath).isDirectory()) {
    throw new ValidationError('out path must be directory');
  }

  const plaintext = fs.readFileSync(inPath);
  const salt = Buffer.allocUnsafe(consts.salt.bytes);
  crypto.randomFillSync(salt);
  const iv = Buffer.allocUnsafe(consts.iv.bytes);
  crypto.randomFillSync(iv);
  const pad = Buffer.allocUnsafe(consts.key.bytes);
  crypto.randomFillSync(pad);
  const {ciphertext, authTag} =
    crypt.encrypt(plaintext, password, salt, iterations, iv, pad);
  const allFragments = padfrag.encode(pad, quorum, totalParticipants);
  allFragments.forEach((fragments, i) => {
    file.write(path.join(outPath, `${i}.tlr-shard`), quorum, iterations, iv, salt, authTag, fragments, ciphertext);
  });
}

function restore(inPaths, outPath, password) {
  let state = null;
  let pad = null;
  fragmentSearch: for (let i = 0; i < inPaths.length; i++) {
    const inPath = inPaths[i];
    const buf = fs.readFileSync(inPath);
    const contents = file.read(buf);
    if (state === null) {
      state = {
        fragDecoder: new padfrag.Decoder(contents.quorum),
        quorum: contents.quorum,
        iterations: contents.iter,
        iv: contents.iv,
        salt: contents.salt,
        authTag: contents.authTag,
        ciphertext: contents.ciphertext,
      };
    }
    if (state.quorum !== contents.quorum) {
      throw new ValidationError('quorum mismatch');
    }
    if (state.iterations !== contents.iter) {
      throw new ValidationError('iterations mismatch');
    }
    if (!state.iv.equals(contents.iv)) {
      throw new ValidationError('iv mismatch');
    }
    if (!state.salt.equals(contents.salt)) {
      throw new ValidationError('salt mismatch');
    }
    if (!state.authTag.equals(contents.authTag)) {
      throw new ValidationError('authTag mismatch');
    }
    for (const [id, frag] of contents.fragments) {
      pad = state.fragDecoder.addFragment(id, frag);
      if (pad !== null) {
        break fragmentSearch;
      }
    }
  }
  if (pad === null) {
    throw new ValidationError('could not reach quorum');
    return;
  }
  const plaintext = crypt.decrypt(state.ciphertext, password, state.salt, state.iterations, state.iv, pad, state.authTag);
  fs.writeFileSync(outPath, plaintext);
}

module.exports = {prepare, restore};
