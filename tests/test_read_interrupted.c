/* SPDX-License-Identifier: LGPL-2.1+ */

/*
 * Regression test: reading a virtualised procfs file must never be reported
 * as a clean EOF just because the FUSE worker thread got interrupted.
 *
 * LXCFS enables FUSE interrupts (cfg->intr = 1). Whenever the *reading* task
 * receives a signal, the kernel sends FUSE_INTERRUPT and libfuse raises
 * LXCFS_INTR_SIGNAL on the worker thread serving the request. Helpers that
 * used bare stdio (getline() does not restart on EINTR) would then fail, and
 * the read handlers used to "return 0" on failure -- which FUSE reports to the
 * caller as end-of-file, i.e. an empty file.
 *
 * This test hammers a file while delivering SIGCHLD to itself (handler
 * installed *without* SA_RESTART, which is what libuv/Node.js does) and fails
 * if any read at offset 0 comes back with 0 bytes.
 *
 * Before the fix this reproduces in well under 150k iterations on a
 * high-core-count host; a quiet loop never reproduces it, so the signal
 * traffic is the essential part of this test.
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void sigchld_handler(int sig)
{
	(void)sig;
}

static ssize_t read_once(const char *path, char *buf, size_t buflen, int *saved_errno)
{
	int fd;
	ssize_t bytes_read;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		*saved_errno = errno;
		return -1;
	}

	errno = 0;
	bytes_read = read(fd, buf, buflen);
	*saved_errno = errno;
	close(fd);

	return bytes_read;
}

int main(int argc, char *argv[])
{
	char buf[8192];
	const char *path;
	long iterations = 20000;
	long empty = 0, failed = 0, ok = 0;
	struct sigaction sa;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <file> [iterations]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	path = argv[1];
	if (argc > 2)
		iterations = atol(argv[2]);

	/*
	 * Deliberately no SA_RESTART: we want the signal to interrupt the
	 * blocking read() so that the kernel sends FUSE_INTERRUPT.
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGCHLD, &sa, NULL) < 0) {
		fprintf(stderr, "sigaction(SIGCHLD) failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	for (long i = 0; i < iterations; i++) {
		int saved_errno = 0;
		ssize_t bytes_read;
		pid_t pid;

		/* Generate signal traffic while the read is in flight. */
		pid = fork();
		if (pid == 0)
			_exit(EXIT_SUCCESS);

		bytes_read = read_once(path, buf, sizeof(buf), &saved_errno);
		if (bytes_read == 0) {
			empty++;
			fprintf(stderr,
				"FAIL: %s returned 0 bytes (reported as EOF) on iteration %ld, errno=%d (%s)\n",
				path, i, saved_errno, strerror(saved_errno));
		} else if (bytes_read < 0) {
			/*
			 * A real error is acceptable: the caller can tell
			 * something went wrong. Silent truncation is not.
			 */
			failed++;
		} else {
			ok++;
		}

		while (waitpid(-1, NULL, WNOHANG) > 0)
			;

		if (empty)
			break;
	}

	printf("%s: iterations=%ld ok=%ld errors=%ld empty=%ld\n",
	       path, iterations, ok, failed, empty);

	if (empty) {
		fprintf(stderr,
			"FAIL: a failed read was reported as end-of-file; "
			"read handlers must return a negative errno instead of 0\n");
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
