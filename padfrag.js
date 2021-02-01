'use strict';

const crypto = require('crypto');
const Combinatorics = require('js-combinatorics');

const consts = require('./consts');

function encode(
  pad /* Buffer(x20) */,
  quorum /* number > 0 */,
  totalParticipants /* number >= quorum */,
) /* Array<
       Array<
         {id: number, contents: Buffer(x20)},
         choose(totalParticipants, quorum)
       >,
       totalParticipants
     > */ {
  if (pad.length !== consts.key.bytes) {
    throw new ArgumentError('bad pad length');
  }
  if (quorum <= 0) {
    throw new ArgumentError('quorum must be positive');
  }
  if (totalParticipants <= quorum) {
    throw new ArgumentError('total participants must not be less than quorum');
  }
  const result = [];
  const participants = [];
  for (let i = 0; i < totalParticipants; i++) {
    result.push([]);
    participants.push(i);
  }
  const cmb = Combinatorics.combination(participants, quorum);
  for (let i = 0;; i++) {
    const sequence = cmb.next();
    if (!sequence) {
      break;
    }
    const acc = Buffer.from(pad);
    const curr = Buffer.allocUnsafe(consts.key.bytes);
    for (let j = 0; j < sequence.length - 1; j++) {
      crypto.randomFillSync(curr);
      result[sequence[j]].push({id: i, contents: Buffer.from(curr)});
      for (let k = 0; k < consts.key.bytes; k++) {
        acc[k] ^= curr[k];
      }
    }
    result[sequence[sequence.length - 1]].push({id: i, contents: acc});
  }
  return result;
}

class Decoder {
  sequences = new Map/* <number, {count: number, contents: Buffer}> */();

  constructor(quorum /* number >= 0 */) {
    this.quorum = quorum;
  }

  addFragment(id /* number */, contents /* Buffer(x20) */) /* Buffer(x20) | null */ {
    if (!this.sequences.has(id)) {
      this.sequences.set(id, {count: 0, contents: Buffer.alloc(consts.key.bytes)});
    }

    const sequence = this.sequences.get(id);
    for (let i = 0; i < consts.key.bytes; i++) {
      sequence.contents[i] ^= contents[i];
    }
    if (++sequence.count === this.quorum) {
      return sequence.contents;
    } else {
      return null;
    }
  }
}

module.exports = {encode, Decoder};
