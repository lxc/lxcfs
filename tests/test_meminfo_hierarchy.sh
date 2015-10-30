#!/bin/bash

set -eux

LXCFSDIR=${LXCFSDIR:-/var/lib/lxcfs}

cg1=x1.$$
cg2=x2.$$
curcg=$(cgm getpidcgroupabs memory $$)

cleanup() {
	cgm movepidabs memory ${curcg} $$
	cgm remove memory ${cg1} 1
	if [ $FAILED -eq 1 ]; then
		echo "Failed"
		exit 1
	fi
	echo "Passed"
	exit 0
}

FAILED=1
trap cleanup EXIT HUP INT TERM

cgm create memory ${cg1}
cgm setvalue memory ${cg1} memory.limit_in_bytes 500000000
cgm movepid memory ${cg1} $$
m1=`awk '/^MemTotal:/ { print $2 }' /var/lib/lxcfs/proc/meminfo`
cgm create memory ${cg2}
cgm movepid memory ${cg2} $$
m2=`awk '/^MemTotal:/ { print $2 }' /var/lib/lxcfs/proc/meminfo`
[ $m1 -eq $m2 ]

FAILED=0
