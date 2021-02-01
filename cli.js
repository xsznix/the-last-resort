'use strict';

const getopt = require('node-getopt');
const readlineSync = require('readline-sync');

const main = require('./main');

let opts, password;
switch (process.argv[2]) {
  case 'prepare':
  opts = getopt.create([
    ['q', 'quorum=QUORUM', 'Number of recovery files needed to restore the key'],
    ['t', 'total=TOTAL', 'Total number of recovery files to generate'],
    ['i', 'input=INPUT', 'File to encrypt'],
    ['o', 'output=OUTPUT', 'Directory to place recovery files in'],
    ['', 'iterations=ITERATIONS', 'Number of PBKDF2 iterations (default: 100,000)', 100000],
    ['h', 'help', 'Show help'],
  ]).bindHelp().parse(process.argv.slice(3)).options;
  password = getPassword();
  main.prepare(opts.input, opts.output, password, +opts.iterations, +opts.quorum, +opts.total);
  break;

  case 'restore':
  opts = getopt.create([
    ['o', 'output=OUTPUT', 'Where to place the restored file'],
    ['h', 'help', 'Show help'],
  ]).bindHelp().parse(process.argv.slice(3));
  password = getPassword();
  main.restore(opts.argv, opts.options.output, password);
  break;

  default:
  console.log('Unrecognized command.');
}

function getPassword() {
  return readlineSync.question('Password: ', {hideEchoBack: true});
}
