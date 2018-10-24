#!/bin/sh
./read_bin.c.out "$1" > "$1__tmp"
echo -n "Number of tcp packets: "
awk '/tcp/' "$1__tmp" | wc -l
echo -n "Number of udp packets: "
awk '/udp/' "$1__tmp" | wc -l
echo ''
echo -e "MSS\tNo."
awk '/tcp/ {print $10}' "$1__tmp" |sort | uniq -c | awk '{printf("%s\t%s\n", $2, $1)}'
echo ''
echo -e "DSCP\tNo."
awk '/dscp/ {print $8}' "$1__tmp" | sort | uniq -c | awk '{printf("%s\t%s\n", $2, $1)}'
