#!/bin/bash

set -ex

[ $(id -u) -eq 0 ]

# Run lxcfs testsuite
export LXCFSDIR=$(mktemp -d)

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
	umount -l ${LXCFSDIR}
	rmdir ${LXCFSDIR}
	if [ ${FAILED} -eq 1 ]; then
		echo "FAILED at $TESTCASE"
		exit 1
	fi
	echo PASSED
	exit 0
}

TESTCASE="setup"
lxcfs=${topdir}/lxcfs

echo "Running ${lxcfs} ${LXCFSDIR}"
${lxcfs} ${LXCFSDIR} &
p=$!

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

TESTCASE="test_proc"
${dirname}/test_proc
TESTCASE="test_cgroup"
${dirname}/test_cgroup
TESTCASE="test_read_proc.sh"
${dirname}/test_read_proc.sh
TESTCASE="cpusetrange"
${dirname}/cpusetrange

FAILED=0
