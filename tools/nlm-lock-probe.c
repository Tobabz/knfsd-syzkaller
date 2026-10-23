/* Minimal POSIX record-lock probe for the disposable NFSv3 guest. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET };
	int fd, hold = 0;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "usage: %s PATH [HOLD_SECONDS]\n", argv[0]);
		return 2;
	}
	if (argc == 3) {
		char *end;
		long value = strtol(argv[2], &end, 10);
		if (*end || value < 0 || value > 60) {
			fprintf(stderr, "invalid hold seconds\n");
			return 2;
		}
		hold = (int)value;
	}
	puts("OPEN_BEGIN");
	fflush(stdout);
	fd = open(argv[1], O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	puts("OPEN_OK");
	fflush(stdout);
	puts("LOCK_BEGIN");
	fflush(stdout);
	if (fcntl(fd, F_SETLKW, &lock) < 0) {
		perror("F_SETLKW");
		close(fd);
		return 1;
	}
	puts("LOCK_OK");
	fflush(stdout);
	sleep((unsigned int)hold);
	lock.l_type = F_UNLCK;
	if (fcntl(fd, F_SETLK, &lock) < 0) {
		perror("F_UNLCK");
		close(fd);
		return 1;
	}
	puts("UNLOCK_OK");
	close(fd);
	return 0;
}
