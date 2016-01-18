# lxcfs

## Introduction
FUSE filesystem for LXC, offering the following features:
 - a cgroupfs compatible view for unprivileged containers
 - a set of cgroup-aware files:
   - cpuinfo
   - meminfo
   - stat
   - uptime

In other words, it will provide an emulated `/proc` and `/sys/fs/cgroup` folder for the containers.

## Usage
The recommended command to run lxcfs is:

    sudo mkdir -p /var/lib/lxcfs
    sudo lxcfs -s -f -o allow_other /var/lib/lxcfs

 - -s is required to turn off multi-threading as libnih-dbus isn't thread safe.
 - -f is to keep lxcfs running in the foreground
 - -o allow\_other is required to have non-root user be able to access the filesystem


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
