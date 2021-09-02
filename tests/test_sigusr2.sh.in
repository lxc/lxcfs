#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1+

set -eu
[ -n "${DEBUG:-}" ] && set -x

PASS=0

cleanup() {
    [ "$PASS" = "1" ] || (echo FAIL && exit 1)
}

trap cleanup EXIT HUP INT TERM

LXCFSDIR=${LXCFSDIR:-/var/lib/lxcfs}

if ! mountpoint -q ${LXCFSDIR}; then
    echo "lxcfs isn't mounted on ${LXCFSDIR}"
    exit 1
fi

echo "==> Setting up memory cgroup in lxcfs_test_proc"
[ ! -d /sys/fs/cgroup/memory ] && exit 0

initmemory=`awk -F: '/memory/ { print $3 }' /proc/1/cgroup`
mempath=/sys/fs/cgroup/memory/${initmemory}
rmdir ${mempath}/lxcfs_test_proc 2>/dev/null || true
mkdir ${mempath}/lxcfs_test_proc
echo 1 > ${mempath}/lxcfs_test_proc/tasks

echo $((64*1024*1024)) > ${mempath}/lxcfs_test_proc/memory.limit_in_bytes

# Test meminfo
echo "==> Testing /proc/meminfo"
[ "$(grep "^MemTotal:.*kB$" ${LXCFSDIR}/proc/meminfo)" = "$(grep "^MemTotal:.*kB$"  /proc/meminfo)" ]

PASS=1
