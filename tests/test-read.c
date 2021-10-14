/* SPDX-License-Identifier: LGPL-2.1+ */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define BUFSIZE 1025
char buf[BUFSIZE];

int read_count = 2;

int main(int argc, char *argv[]){
	if(argc < 3){
		fprintf(stderr, "usage: %s <file> <count> [buffer|direct]\n", argv[0]);
		exit(1);
	}
	char *file = argv[1];
	read_count = atoi(argv[2]);
	int ret = 0,sum = 0, i = 0, fd = -1;
	if(argc == 4 && strncmp(argv[3], "direct",6) == 0)
		fd = open(file, O_RDONLY|O_DIRECT);
	else
		fd = open(file, O_RDONLY);

	while(i++ < read_count){
		memset(buf, 0, BUFSIZE);
		ret = read(fd, buf, BUFSIZE-1);
		if(ret > 0){
			write(STDOUT_FILENO, buf, ret);
			sum += ret;
		}else if(ret == 0){
			printf("======read end======\n");
			break;
		}else{
			printf("error:%d\n", errno);
			break;
		}
		sleep(1);
	}
	printf("======read sum: %d======\n", sum);
	close(fd);
	return 0;
}
