# lxcfs

FUSE filesystem for LXC, offering the following features:
 - a cgroupfs compatible view for unprivileged containers
 - a set of cgroup-aware files:
   - cpuinfo
   - meminfo
   - stat
   - uptime

### Usage

The recommended command to run lxcfs is:

	sudo mkdir -p /var/lib/lxcfs
	sudo lxcfs -s -f -d -o allow_other /var/lib/lxcfs

We recommend -s to avoid threading;  -o allow_other is needed to
allow users other than root to use the filesystem.
