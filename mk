#!/bin/sh

#cc -ltrace -lmd $1 -o $1.out -I/usr/local/include -L/usr/local/lib -pg
#cc -ltrace -lmd $1 -o $1.out -I/usr/local/include -L/usr/local/lib
cc -ltrace -lmd $1 -o $1.out -I/root/lib/include -L/root/lib/lib/  -g -fprofile-instr-generate -fcoverage-mapping
