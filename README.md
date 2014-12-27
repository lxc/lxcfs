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
