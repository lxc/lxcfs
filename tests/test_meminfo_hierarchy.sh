#!/bin/bash

set -eux

LXCFSDIR=${LXCFSDIR:-/var/lib/lxcfs}

cg1=$(uuidgen).$$
cg2=$(uuidgen).$$

cleanup() {
	if [ $FAILED -eq 1 ]; then
		echo "Failed"
		exit 1
	fi
	echo "Passed"
	exit 0
}

FAILED=1
trap cleanup EXIT HUP INT TERM

[ ! -d /sys/fs/cgroup/memory ] && exit 0
initmemory=`awk -F: '/memory/ { print $3 }' /proc/1/cgroup`
mempath=/sys/fs/cgroup/memory/${initmemory}
rmdir ${mempath}/${cg1} || true
rmdir ${mempath}/${cg2} || true
mkdir ${mempath}/${cg1}

echo 500000000 > ${mempath}/${cg1}/memory.limit_in_bytes
echo 1 > ${mempath}/${cg1}/tasks

m1=`awk '/^MemTotal:/ { print $2 }' ${LXCFSDIR}/proc/meminfo`
mkdir ${mempath}/${cg1}/${cg2}
echo 1 > ${mempath}/${cg1}/${cg2}/tasks
m2=`awk '/^MemTotal:/ { print $2 }' ${LXCFSDIR}/proc/meminfo`
[ $m1 -eq $m2 ]

FAILED=0
