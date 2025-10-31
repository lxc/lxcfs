/* Borrowed from https://www.kernel.org/doc/Documentation/accounting/psi.rst */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WAIT_EVENTS_NUM 4

/*
* Monitor cpu partial stall with 2s tracking window size
* and 20ms threshold.
*/
int main(int argc, char **argv) {
	const char trig[] = "some 20000 2000000";
	struct pollfd fds;
	int n;
	char *path;
	size_t len;
	int events_cnt = 0;

	if (geteuid() != 0) {
		fprintf(stderr, "Run me as root\n");
		exit(1);
	}

	if (argc != 2)  {
		fprintf(stderr, "Usage: %s [lxcfs_mount_path]\n", argv[0]);
		exit(1);
	}

	len = strlen(argv[1]) + strlen("/proc/pressure/cpu") + 1;
	path = alloca(len);
	snprintf(path, len, "%s/proc/pressure/cpu", argv[1]);
	fds.fd = open(path, O_RDWR | O_NONBLOCK);
	if (fds.fd < 0) {
		printf("%s open error: %s\n", path, strerror(errno));
		return 1;
	}
	fds.events = POLLPRI;

	if (write(fds.fd, trig, strlen(trig) + 1) < 0) {
		printf("/proc/pressure/cpu write error: %s\n",
			strerror(errno));
		return 1;
	}

	printf("waiting for events...\n");
	time_t t1 = time(NULL);
	while (1) {
		/* test code in proc_fuse.c poll_thread() generates 1 event per second */
		n = poll(&fds, 1, 3 * 1000);
		if (n < 0) {
			printf("poll error: %s\n", strerror(errno));
			return 1;
		}
		if (n == 0) {
			printf("timeout\n");
			return 1;
		}
		if (fds.revents & POLLERR) {
			printf("got POLLERR, event source is gone\n");
			return 1;
		}
		if (fds.revents & POLLPRI) {
			printf("event triggered!\n");
			events_cnt++;
			if (events_cnt == WAIT_EVENTS_NUM)
				break;
		} else {
			printf("unknown event received: 0x%x\n", fds.revents);
			return 1;
		}
	}
	time_t t2 = time(NULL);

	printf("events_cnt = %d time diff = %ld\n", events_cnt, (long)(t2 - t1));
	/* events frequency is 1 HZ, so we can expect that difference <= 1 */
	if (labs((long)(t2 - t1) - events_cnt) > 1) {
		printf("| (t2 - t1) - events_cnt | > 1 while should be <= 1\n");
		return 1;
	}

	return 0;
}
