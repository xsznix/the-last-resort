#!/bin/sh

mkdir -p test/out
echo arbitrary test data > test/in.txt
node cli.js prepare -q3 -t6 -i test/in.txt -o test/out
node cli.js restore -o test/result.txt test/out/1.tlr-shard test/out/3.tlr-shard test/out/5.tlr-shard
diff test/in.txt test/result.txt
