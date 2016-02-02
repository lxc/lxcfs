#!/bin/bash

set -ex

UUID=$(uuidgen)

[ $(id -u) -eq 0 ]

d=$(mktemp -t -d tmp.XXX)
d2=$(mktemp -t -d tmp.XXX)

pid=-1
cleanup() {
	[ $pid -ne -1 ] && kill -9 $pid
	umount -l $d || true
	umount -l $d2 || true
	rm -rf $d $d2
}

cmdline=$(realpath $0)
dirname=$(dirname ${cmdline})
topdir=$(dirname ${dirname})

trap cleanup EXIT HUP INT TERM

${topdir}/lxcfs $d &
pid=$!

# put ourselves into x1
cgm movepidabs freezer / 1
cgm create freezer x1
cgm movepid freezer x1 1

mount -t cgroup -o freezer freezer $d2
sudo rmdir $d2/${UUID}_a1/${UUID}_a2 || true
sudo rmdir $d2/${UUID}_a1 || true

echo "Making sure root cannot mkdir"
bad=0
mkdir $d/cgroup/freezer/${UUID}_a1 && bad=1
if [ "${bad}" -eq 1 ]; then
	false
fi

echo "Making sure root cannot rmdir"
mkdir $d2/${UUID}_a1
mkdir $d2/${UUID}_a1/${UUID}_a2
rmdir $d/cgroup/freezer/${UUID}_a1 && bad=1
if [ "${bad}" -eq 1 ]; then
	false
fi
[ -d $d2/${UUID}_a1 ]
rmdir $d/cgroup/freezer/${UUID}_a1/${UUID}_a2 && bad=1
if [ "${bad}" -eq 1 ]; then
	false
fi
[ -d $d2/${UUID}_a1/${UUID}_a2 ]

echo "Making sure root cannot read/write"
sleep 200 &
p=$!
echo $p > $d/cgroup/freezer/${UUID}_a1/tasks && bad=1
if [ "${bad}" -eq 1 ]; then
	false
fi
cat $d/cgroup/freezer/${UUID}_a1/tasks && bad=1
if [ "${bad}" -eq 1 ]; then
	false
fi
echo $p > $d/cgroup/freezer/${UUID}_a1/${UUID}_a2/tasks && bad=1
if [ "${bad}" -eq 1 ]; then
	false
fi
cat $d/cgroup/freezer/${UUID}_a1/${UUID}_a2/tasks && bad=1
if [ "${bad}" -eq 1 ]; then
	false
fi

# make sure things like truncate and access don't leak info about
# the /${UUID}_a1 cgroup which we shouldn't be able to reach
echo "Testing other system calls"
${dirname}/test_syscalls $d/cgroup/freezer/${UUID}_a1
${dirname}/test_syscalls $d/cgroup/freezer/${UUID}_a1/${UUID}_a2

echo "Making sure root can act on descendents"
mycg=$(cgm getpidcgroupabs freezer 1)
newcg=${mycg}/${UUID}_a1
rmdir $d2/$newcg || true  # cleanup previosu run
mkdir $d/cgroup/freezer/$newcg
echo $p > $d/cgroup/freezer/$newcg/tasks
cat $d/cgroup/freezer/$newcg/tasks
kill -9 $p
while [ `wc -l $d/cgroup/freezer/$newcg/tasks | awk '{ print $1 }'` -ne 0 ]; do
	sleep 1
done
rmdir $d/cgroup/freezer/$newcg

echo "All tests passed!"
