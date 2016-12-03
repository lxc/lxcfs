#!/bin/sh -eux

PASS=0
UUID=$(uuidgen)

cleanup() {
    [ "$PASS" = "1" ] || (echo FAIL && exit 1)
}

LXCFSDIR=${LXCFSDIR:-/var/lib/lxcfs}

trap cleanup EXIT HUP INT TERM

if ! mountpoint -q ${LXCFSDIR}; then
    echo "lxcfs isn't mounted on ${LXCFSDIR}"
    exit 1
fi

for c in memory freezer cpuset; do
	[ ! -d /sys/fs/cgroup/${c} ] && exit 0
done

initcpuset=`awk -F: '/cpuset/ { print $3 }' /proc/1/cgroup`
initmemory=`awk -F: '/memory/ { print $3 }' /proc/1/cgroup`
initfreezer=`awk -F: '/freezer/ { print $3 }' /proc/1/cgroup`

cpupath=/sys/fs/cgroup/cpuset/${initcpuset}
mempath=/sys/fs/cgroup/memory/${initmemory}
frzpath=/sys/fs/cgroup/freezer/${initfreezer}

rmdir ${cpupath}/${UUID} || true
rmdir ${mempath}/${UUID} || true
rmdir ${frzpath}/${UUID} || true
mkdir ${cpupath}/${UUID}
mkdir ${mempath}/${UUID}
mkdir ${frzpath}/${UUID}

# Check that the fs is readable
for p in ${mempath} ${frzpath} ${cpupath}; do
	find ${p} > /dev/null
	echo 1 > ${p}/${UUID}/tasks
done

# set values though lxcfs
echo $((64*1024*1024)) > ${LXCFSDIR}/cgroup/memory/${initmemory}/${UUID}/memory.limit_in_bytes
echo 0 > ${LXCFSDIR}/cgroup/cpuset/${initcpuset}/${UUID}/cpuset.cpus

# and verify them through cgroupfs
v=`cat $mempath/${UUID}/memory.limit_in_bytes`
[ "$v" = "$((64*1024*1024))" ]
v=`cat ${cpupath}/${UUID}/cpuset.cpus`
[ "$v" = "0" ]

PASS=1
echo PASS
