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

[ ! -d /sys/fs/cgroup/cpuset ] && exit 0

# Test cpuinfo
[ "$(grep "^processor" ${LXCFSDIR}/proc/cpuinfo | wc -l)" = "$(grep "^processor" /proc/cpuinfo | wc -l)" ]

PASS=1
