#!/bin/sh -eux

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

[ ! -d /sys/fs/cgroup/memory ] && exit 0
[ ! -d /sys/fs/cgroup/cpuset ] && exit 0

initcpuset=`awk -F: '/cpuset/ { print $3 }' /proc/1/cgroup`
initmemory=`awk -F: '/memory/ { print $3 }' /proc/1/cgroup`

cpupath=/sys/fs/cgroup/cpuset/${initcpuset}
mempath=/sys/fs/cgroup/memory/${initmemory}

rmdir ${cpupath}/lxcfs_test_proc || true
rmdir ${mempath}/lxcfs_test_proc || true
mkdir ${cpupath}/lxcfs_test_proc
mkdir ${mempath}/lxcfs_test_proc

echo 1 > ${cpupath}/lxcfs_test_proc/tasks
echo 1 > ${mempath}/lxcfs_test_proc/tasks

echo $((64*1024*1024)) > ${mempath}/lxcfs_test_proc/memory.limit_in_bytes
echo 0 > ${cpupath}/lxcfs_test_proc/cpuset.cpus

# Test uptime
[ "$(cat ${LXCFSDIR}/proc/uptime)" = "0.00 0.00" ]

# Test cpuinfo
[ "$(grep "^processor" ${LXCFSDIR}/proc/cpuinfo | wc -l)" = "1" ]
grep -q "^processor.*0$" ${LXCFSDIR}/proc/cpuinfo || grep -q "^processor 0:.*" ${LXCFSDIR}/proc/cpuinfo

# Test stat
[ "$(grep "^cpu" ${LXCFSDIR}/proc/stat | wc -l)" = "2" ]

# Test meminfo
grep -q "^MemTotal.*65536 kB$" ${LXCFSDIR}/proc/meminfo

PASS=1
echo PASS
