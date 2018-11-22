#!/bin/sh
cc -ltrace -lmd probe.c -o probe.out -I/usr/local/include -L/usr/local/lib
cc read_bin.c -o read.out -I/usr/local/include -L/usr/local/lib
cc read_stats.c -o read_stats.out -I/usr/local/include -L/usr/local/lib
