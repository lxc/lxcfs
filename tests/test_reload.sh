#!/bin/bash

set -ex

[ $(id -u) -eq 0 ]

cmdline=$(realpath $0)
dirname=$(dirname ${cmdline})
topdir=$(dirname ${dirname})

testdir=`mktemp -t -d libs.XXX`
installdir=`mktemp -t -d libs.XXX`
pidfile=$(mktemp)
libdir=${installdir}/usr/lib
bindir=${installdir}/usr/bin
lxcfspid=-1
FAILED=1

cleanup() {
  if [ ${lxcfspid} -ne -1 ]; then
    kill -9 ${lxcfspid}
    count=1
    while [ -d ${testdir}/proc -a $count -lt 5 ]; do
      sleep 1
    done
    umount -l ${testdir}
  fi
  rm -rf ${testdir} ${installdir}
  rm -f /tmp/lxcfs-iwashere
  rm -f ${pidfile}
  if [ ${FAILED} -eq 1 ]; then
    echo "liblxcfs.so reload test FAILED"
  else
    echo "liblxcfs.so reload test PASSED"
  fi
}

trap cleanup EXIT SIGHUP SIGINT SIGTERM

( cd ${topdir}; DESTDIR=${installdir} make install )
export LD_LIBRARY_PATH=${libdir}

${bindir}/lxcfs -p ${pidfile} ${testdir} &

lxcfspid=$!
count=1
while [ ! -d ${testdir}/proc ]; do
  [ $count -lt 5 ]
  sleep 1
  count=$((count+1))
done

rm -f /tmp/lxcfs-iwashere
cat ${testdir}/proc/uptime
[ ! -f /tmp/lxcfs-iwashere ]
(
  cd ${topdir};
  make liblxcfstest.la
  gcc -shared -fPIC -DPIC .libs/liblxcfstest_la-bindings.o .libs/liblxcfstest_la-cpuset.o -lpthread -pthread -o .libs/liblxcfstest.so
  cp .libs/liblxcfstest.* "${libdir}"
)
rm -f ${libdir}/liblxcfs.so* ${libdir}/liblxcfs.la
cp ${libdir}/liblxcfstest.so ${libdir}/liblxcfs.so

kill -USR1 ${lxcfspid}

cat ${testdir}/proc/uptime
[ -f /tmp/lxcfs-iwashere ]
FAILED=0
