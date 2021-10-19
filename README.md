# lxcfs

## Introduction
LXCFS is a small FUSE filesystem written with the intention of making Linux
containers feel more like a virtual machine. It started as a side-project of
`LXC` but is useable by any runtime.

LXCFS will take care that the information provided by crucial files in `procfs`
such as:

```
/proc/cpuinfo
/proc/diskstats
/proc/meminfo
/proc/stat
/proc/swaps
/proc/uptime
/proc/slabinfo
/sys/devices/system/cpu
/sys/devices/system/cpu/online
```

are container aware such that the values displayed (e.g. in `/proc/uptime`)
really reflect how long the container is running and not how long the host is
running.

Prior to the implementation of cgroup namespaces by Serge Hallyn `LXCFS` also
provided a container aware `cgroupfs` tree. It took care that the container
only had access to cgroups underneath it's own cgroups and thus provided
additional safety. For systems without support for cgroup namespaces `LXCFS`
will still provide this feature but it is mostly considered deprecated.

## Upgrading `LXCFS` without restart

`LXCFS` is split into a shared library (a libtool module, to be precise)
`liblxcfs` and a simple binary `lxcfs`. When upgrading to a newer version of
`LXCFS` the `lxcfs` binary will not be restarted. Instead it will detect that
a new version of the shared library is available and will reload it using
`dlclose(3)` and `dlopen(3)`. This design was chosen so that the fuse main loop
that `LXCFS` uses will not need to be restarted. If it were then all containers
using `LXCFS` would need to be restarted since they would otherwise be left
with broken fuse mounts.

To force a reload of the shared library at the next possible instance simply
send `SIGUSR1` to the pid of the running `LXCFS` process. This can be as simple
as doing:

    rm /usr/lib64/lxcfs/liblxcfs.so # MUST to delete the old library file first
    cp liblxcfs.so /usr/lib64/lxcfs/liblxcfs.so # to place new library file
    kill -s USR1 $(pidof lxcfs) # reload

### musl

To achieve smooth upgrades through shared library reloads `LXCFS` also relies
on the fact that when `dlclose(3)` drops the last reference to the shared
library destructors are run and when `dlopen(3)` is called constructors are
run. While this is true for `glibc` it is not true for `musl` (See the section
[Unloading libraries](https://wiki.musl-libc.org/functional-differences-from-glibc.html).).
So users of `LXCFS` on `musl` are advised to restart `LXCFS` completely and all
containers making use of it.

## Building

In order to build LXCFS install fuse and the fuse development headers according
to your distro. LXCFS prefers `fuse3` but does work with new enough `fuse2`
versions:

    git clone git://github.com/lxc/lxcfs
    cd lxcfs
    meson setup -Dinit-script=systemd --prefix=/usr build/
    meson compile -C build/
    sudo meson install -C build/

## Usage
The recommended command to run lxcfs is:

    sudo mkdir -p /var/lib/lxcfs
    sudo lxcfs /var/lib/lxcfs

A container runtime wishing to use `LXCFS` should then bind mount the
approriate files into the correct places on container startup.

### LXC
In order to use lxcfs with systemd-based containers, you can either use
LXC 1.1 in which case it should work automatically, or otherwise, copy
the `lxc.mount.hook` and `lxc.reboot.hook` files (once built) from this tree to
`/usr/share/lxcfs`, make sure it is executable, then add the
following lines to your container configuration:
```
lxc.mount.auto = cgroup:mixed
lxc.autodev = 1
lxc.kmsg = 0
lxc.include = /usr/share/lxc/config/common.conf.d/00-lxcfs.conf
```

## Using with Docker

```
docker run -it -m 256m --memory-swap 256m \
      -v /var/lib/lxcfs/proc/cpuinfo:/proc/cpuinfo:rw \
      -v /var/lib/lxcfs/proc/diskstats:/proc/diskstats:rw \
      -v /var/lib/lxcfs/proc/meminfo:/proc/meminfo:rw \
      -v /var/lib/lxcfs/proc/stat:/proc/stat:rw \
      -v /var/lib/lxcfs/proc/swaps:/proc/swaps:rw \
      -v /var/lib/lxcfs/proc/uptime:/proc/uptime:rw \
      -v /var/lib/lxcfs/proc/slabinfo:/proc/slabinfo:rw \
      ubuntu:18.04 /bin/bash
 ```

 In a system with swap enabled, the parameter "-u" can be used to set all values in "meminfo" that refer to the swap to 0.

 sudo lxcfs -u /var/lib/lxcfs

## Swap handling
If you noticed LXCFS not showing any SWAP in your container despite
having SWAP on your system, please read this section carefully and look
for instructions on how to enable SWAP accounting for your distribution.

Swap cgroup handling on Linux is very confusing and there just isn't a
perfect way for LXCFS to handle it.

Terminology used below:
 - RAM refers to `memory.usage_in_bytes` and `memory.limit_in_bytes`
 - RAM+SWAP refers to `memory.memsw.usage_in_bytes` and `memory.memsw.limit_in_bytes`

The main issues are:
 - SWAP accounting is often opt-in and, requiring a special kernel boot
   time option (`swapaccount=1`) and/or special kernel build options
   (`CONFIG_MEMCG_SWAP`).

 - Both a RAM limit and a RAM+SWAP limit can be set. The delta however
   isn't the available SWAP space as the kernel is still free to SWAP as
   much of the RAM as it feels like. This makes it impossible to render
   a SWAP device size as using the delta between RAM and RAM+SWAP for that
   wouldn't account for the kernel swapping more pages, leading to swap
   usage exceeding swap total.

 - It's impossible to disable SWAP in a given container. The closest
   that can be done is setting swappiness down to 0 which severly limits
   the risk of swapping pages but doesn't eliminate it.

As a result, LXCFS had to make some compromise which go as follow:
 - When SWAP accounting isn't enabled, no SWAP space is reported at all.
   This is simply because there is no way to know the SWAP consumption.
   The container may very much be using some SWAP though, there's just
   no way to know how much of it and showing a SWAP device would require
   some kind of SWAP usage to be reported. Showing the host value would be
   completely wrong, showing a 0 value would be equallty wrong.

 - Because SWAP usage for a given container can exceed the delta between
   RAM and RAM+SWAP, the SWAP size is always reported to be the smaller of
   the RAM+SWAP limit or the host SWAP device itself. This ensures that at no
   point SWAP usage will be allowed to exceed the SWAP size.

 - If the swappiness is set to 0 and there is no SWAP usage, no SWAP is reported.
   However if there is SWAP usage, then a SWAP device of the size of the
   usage (100% full) is reported. This provides adequate reporting of
   the memory consumption while preventing applications from assuming more
   SWAP is available.
