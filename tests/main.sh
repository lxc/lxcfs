#!/bin/bash

set -ex

[ $(id -u) -eq 0 ]

# Run lxcfs testsuite
export LXCFSDIR=$(mktemp -d)
pidfile=$(mktemp)

cmdline=$(realpath $0)
dirname=$(dirname ${cmdline})
topdir=$(dirname ${dirname})

p=-1
FAILED=1
cleanup() {
	set +e
	if [ $p -ne -1 ]; then
		kill -9 $p
	fi
	if [ ${LXCFSDIR} != "/var/lib/lxcfs" ]; then
		umount -l ${LXCFSDIR}
		rmdir ${LXCFSDIR}
	fi
	rm -f ${pidfile}
	if [ ${FAILED} -eq 1 ]; then
		echo "FAILED at $TESTCASE"
		exit 1
	fi
	echo PASSED
	exit 0
}

TESTCASE="setup"
lxcfs=${topdir}/lxcfs

if [ -x ${lxcfs} ]; then
	echo "Running ${lxcfs} ${LXCFSDIR}"
	${lxcfs} -p ${pidfile} ${LXCFSDIR} &
	p=$!
else
	pidof lxcfs
	echo "Using host lxcfs"
	rmdir $LXCFSDIR
	export LXCFSDIR=/var/lib/lxcfs
fi

trap cleanup EXIT SIGHUP SIGINT SIGTERM

count=1
while ! mountpoint -q $LXCFSDIR; do
	sleep 1s
	if [ $count -gt 5 ]; then
		echo "lxcfs failed to start"
		false
	fi
	count=$((count+1))
done

RUNTEST() {
	unshare -fmp --mount-proc $*
}

TESTCASE="test_proc"
RUNTEST ${dirname}/test_proc
TESTCASE="test_cgroup"
RUNTEST ${dirname}/test_cgroup
TESTCASE="test_read_proc.sh"
RUNTEST ${dirname}/test_read_proc.sh
TESTCASE="cpusetrange"
RUNTEST ${dirname}/cpusetrange
TESTCASE="meminfo hierarchy"
RUNTEST ${dirname}/test_meminfo_hierarchy.sh
TESTCASE="liblxcfs reloading"
${dirname}/test_reload.sh

# Check for any defunct processes - children we didn't reap
n=`ps -ef | grep lxcfs | grep defunct | wc -l`
[ $n = 0 ]

FAILED=0
