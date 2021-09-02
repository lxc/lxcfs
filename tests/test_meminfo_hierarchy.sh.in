#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1+

set -eu
[ -n "${DEBUG:-}" ] && set -x

LXCFSDIR=${LXCFSDIR:-/var/lib/lxcfs}

cg1=$(uuidgen).$$
cg2=$(uuidgen).$$

cleanup() {
	if [ $FAILED -eq 1 ]; then
		exit 1
	fi
	exit 0
}

FAILED=1
trap cleanup EXIT HUP INT TERM

[ ! -d /sys/fs/cgroup/memory ] && exit 0
echo "==> Setting up memory cgroup"
initmemory=`awk -F: '/memory/ { print $3 }' /proc/1/cgroup`
mempath=/sys/fs/cgroup/memory/${initmemory}
rmdir ${mempath}/${cg1} 2>/dev/null || true
rmdir ${mempath}/${cg2} 2>/dev/null || true

echo "==> Testing /proc/meminfo with limit"
mkdir ${mempath}/${cg1}
echo 500000000 > ${mempath}/${cg1}/memory.limit_in_bytes
echo 1 > ${mempath}/${cg1}/tasks
m1=`awk '/^MemTotal:/ { print $2 }' ${LXCFSDIR}/proc/meminfo`

echo "==> Testing /proc/meminfo with sub-cgroup"
mkdir ${mempath}/${cg1}/${cg2}
echo 1 > ${mempath}/${cg1}/${cg2}/tasks
m2=`awk '/^MemTotal:/ { print $2 }' ${LXCFSDIR}/proc/meminfo`

echo "==> Confirming same limits"
[ $m1 -eq $m2 ]

FAILED=0
