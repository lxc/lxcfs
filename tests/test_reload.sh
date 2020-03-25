#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1+

set -eu
[ -n "${DEBUG:-}" ] && set -x

[ $(id -u) -eq 0 ]

cmdline=$(realpath $0)
dirname=$(dirname ${cmdline})
topdir=$(dirname ${dirname})

testdir=`mktemp -t -d libs.XXX`
installdir=`mktemp -t -d libs.XXX`
pidfile=$(mktemp)
libdir=${installdir}/$(grep ^LIBDIR Makefile | awk '{print $NF}')
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

trap cleanup EXIT HUP INT TERM

echo "==> Installing lxcfs to temporary path"
( cd ${topdir}; DESTDIR=${installdir} make -s install >/dev/null 2>&1)
if [ -n "${LD_LIBRARY_PATH:-}" ]; then
    export LD_LIBRARY_PATH="${libdir}:${LD_LIBRARY_PATH}"
else
    export LD_LIBRARY_PATH=${libdir}
fi

echo "==> Spawning lxcfs"
${bindir}/lxcfs -p ${pidfile} ${testdir} &

lxcfspid=$!

count=1
while [ ! -d ${testdir}/proc ]; do
  [ $count -lt 5 ]
  sleep 1
  count=$((count+1))
done

rm -f /tmp/lxcfs-iwashere

echo "==> Testing that lxcfs is functional"
cat ${testdir}/proc/uptime

[ ! -f /tmp/lxcfs-iwashere ]
(
  cd ${topdir}/src;
  make -s liblxcfstest.la
  gcc -shared -fPIC -DPIC -Wl,-soname,liblxcfs.so .libs/liblxcfstest_la-*.o cgroups/.libs/liblxcfstest_la-*.o -lpthread -pthread -o .libs/liblxcfstest.so
  cp .libs/liblxcfstest.* "${libdir}"
) > /dev/null
rm -f ${libdir}/liblxcfs.so* ${libdir}/liblxcfs.la
cp ${libdir}/liblxcfstest.so ${libdir}/liblxcfs.so

kill -USR1 ${lxcfspid}
sleep 1
cat ${testdir}/proc/uptime
sleep 1
[ -f /tmp/lxcfs-iwashere ]

FAILED=0
