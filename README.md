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
```

are container aware such that the values displayed (e.g. in `/proc/uptime`)
really reflect how long the container is running and not how long the host is
running.

Prior to the implementation of cgroup namespaces by Serge Hallyn `LXCFS` also
provided a container aware `cgroupfs` tree. It took care that the container
only had access to cgroups underneath it's own cgroups and thus provided
additional safety. For systems without support for cgroup namespaces `LXCFS`
will still provide this feature.

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

## Upgrading LXCFS without breaking running containers
LXCFS is implemented using a simple shared library without any external
dependencies other than `FUSE`. It is completely reloadable without having to
umount it. This ensures that container can be kept running even when the shared
library is upgraded.

To force a reload of the shared library at the next possible instance simply
send `SIGUSR1` to the pid of the running `LXCFS` process. This can be as simple
as doing:

    kill -s USR1 $(pidof lxcfs)
