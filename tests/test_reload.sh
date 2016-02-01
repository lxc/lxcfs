#!/bin/bash

set -ex

[ $(id -u) -eq 0 ]

cmdline=$(realpath $0)
dirname=$(dirname ${cmdline})
topdir=$(dirname ${dirname})

testdir=`mktemp -t -d libs.XXX`
installdir=`mktemp -t -d libs.XXX`
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
  rm -f iwashere
  if [ ${FAILED} -eq 1 ]; then
    echo "liblxcfs.so reload test FAILED"
  else
    echo "liblxcfs.so reload test PASSED"
  fi
}

trap cleanup EXIT SIGHUP SIGINT SIGTERM

( cd ${topdir}; DESTDIR=${installdir} make install )
export LD_LIBRARY_PATH=${libdir}

${bindir}/lxcfs ${testdir} &
lxcfspid=$!
count=1
while [ ! -d ${testdir}/proc ]; do
  [ $count -lt 5 ]
  sleep 1
done

rm -f iwashere
cat ${testdir}/proc/uptime
[ ! -f iwashere ]
rm -f ${libdir}/liblxcfs.so* ${libdir}/liblxcfs.la
ln -s liblxcfstest.so.0.0.0 ${libdir}/liblxcfs.so
cp ${libdir}/liblxcfstest.la ${libdir}/liblxcfs.la

kill -USR1 ${lxcfspid}

cat ${testdir}/proc/uptime
[ -f iwashere ]
FAILED=0
