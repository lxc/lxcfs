# lxcfs

## Introduction
FUSE filesystem for LXC, offering the following features:
 - a cgroupfs compatible view for unprivileged containers
 - a set of cgroup-aware files:
   - cpuinfo
   - meminfo
   - stat
   - uptime

## Usage
The recommended command to run lxcfs is:

    sudo mkdir -p /var/lib/lxcfs
    sudo lxcfs -s -f -o allow_other /var/lib/lxcfs

 - -s is required to turn off multi-threading as libnih-dbus isn't thread safe.
 - -f is to keep lxcfs running in the foreground
 - -o allow\_other is required to have non-root user be able to access the filesystem
 - -d can also be passed in order to debug lxcfs

In order to use lxcfs with systemd-based containers, copy the hook.lxcfs
file from this tree to /usr/share/lxc/hooks/lxcfs, make sure it is executable,
then add the following two lines to your container configuration:

lxc.kmsg = 0
lxc.hook.mount = /usr/share/lxc/hooks/lxcfs
