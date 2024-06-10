The template below is mostly useful for bug reports and support questions.
Feel free to remove anything which doesn't apply to you and add more information where it makes sense.

# Required information

 * Distribution:
   * `cat /etc/os-release` or `cat /etc/lsb-release`
 * LXCFS version:
 * The output of
   * `uname -a`
   * `cat /proc/1/mounts`
   * `ps aux | grep lxcfs`
   * LXCFS logs

# Issue description

A brief description of what failed or what could be improved.

If you have LXCFS crashing, please, collect a crash dump.

# Steps to reproduce

 1. Step one
 2. Step two
 3. Step three

# Information to attach

 - [ ] any relevant kernel output (`dmesg`)
 - [ ] LXCFS daemon output / logs
 - [ ] LXCFS configuration (Which options were used to start a LXCFS daemon? `ps aux | grep lxcfs`)
 - [ ] in case of crash, a core dump (please, read [how to collect a core dump](https://github.com/lxc/lxcfs?tab=readme-ov-file#core-dump))
