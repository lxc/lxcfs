/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "../src/cpuset_parse.h"

static void verify(bool condition) {
	if (condition) {
		printf(" PASS\n");
	} else {
		printf(" FAIL!\n");
		exit(1);
	}
}

int main(void) {
	char *a = "1,2";
	char *b = "1-3,5";
	char *c = "1,4-5";
	char *d = "";
	char *e = "\n";

	printf("1 in %s", a);
	verify(cpu_in_cpuset(1, a));
	printf("2 in %s", a);
	verify(cpu_in_cpuset(2, a));
	printf("NOT 4 in %s", a);
	verify(!cpu_in_cpuset(4, a));
	printf("1 in %s", b);
	verify(cpu_in_cpuset(1, b));
	printf("NOT 4 in %s", b);
	verify(!cpu_in_cpuset(4, b));
	printf("5 in %s", b);
	verify(cpu_in_cpuset(5, b));
	printf("1 in %s", c);
	verify(cpu_in_cpuset(1, c));
	printf("5 in %s", c);
	verify(cpu_in_cpuset(5, c));
	printf("NOT 6 in %s", c);
	verify(!cpu_in_cpuset(6, c));
	printf("NOT 6 in empty set");
	verify(!cpu_in_cpuset(6, d));
	printf("NOT 6 in empty set(2)");
	verify(!cpu_in_cpuset(6, e));
}
