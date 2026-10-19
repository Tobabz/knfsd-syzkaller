#define _POSIX_C_SOURCE 200809L
#include "lifecycle.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define INFO_MAX 4096u

struct client_info {
	uint64_t clientid;
	uint32_t minor_version;
	uint32_t session_count;
	int confirmed;
	char name[128];
};

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static void put64(uint8_t *p, uint64_t value)
{
	put32(p, (uint32_t)(value >> 32));
	put32(p + 4, (uint32_t)value);
}

static int numeric_name(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;

	if (*p == '\0')
		return 0;
	for (; *p != '\0'; p++)
		if (*p < (unsigned char)'0' || *p > (unsigned char)'9')
			return 0;
	return 1;
}

static int safe_hostname(const char *name)
{
	const unsigned char *p = (const unsigned char *)name;

	if (*p == '\0')
		return 0;
	for (; *p != '\0'; p++)
		if (!((*p >= (unsigned char)'a' && *p <= (unsigned char)'z') ||
		      (*p >= (unsigned char)'A' && *p <= (unsigned char)'Z') ||
		      (*p >= (unsigned char)'0' && *p <= (unsigned char)'9') ||
		      *p == (unsigned char)'-' || *p == (unsigned char)'.'))
			return 0;
	return 1;
}

static int read_info(int fd, char data[INFO_MAX + 1u])
{
	size_t used = 0;

	for (;;) {
		ssize_t n;

		if (used == INFO_MAX) {
			char extra;

			n = read(fd, &extra, 1);
			if (n < 0 && errno == EINTR)
				continue;
			if (n != 0) {
				errno = n < 0 ? errno : EOVERFLOW;
				return -1;
			}
			break;
		}
		n = read(fd, data + used, INFO_MAX - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -1;
		if (n == 0)
			break;
		used += (size_t)n;
	}
	if (used == 0) {
		errno = EPROTO;
		return -1;
	}
	data[used] = '\0';
	return 0;
}

static int parse_sessions(const char *value, uint32_t *count)
{
	uint32_t n = 0;
	const char *p = value;

	for (;;) {
		char *end;
		unsigned long slot;

		while (*p == ' ')
			p++;
		if (*p == '\0')
			break;
		errno = 0;
		slot = strtoul(p, &end, 10);
		if (errno != 0 || end == p || (*end != ' ' && *end != '\0') ||
		    slot > UINT_MAX || n == UINT32_MAX) {
			errno = EPROTO;
			return -1;
		}
		n++;
		p = end;
	}
	*count = n;
	return 0;
}

static int parse_info(char data[INFO_MAX + 1u], struct client_info *info)
{
	unsigned seen_clientid = 0, seen_status = 0, seen_name = 0;
	unsigned seen_minor = 0, seen_sessions = 0;
	char *save = NULL;
	char *line;

	memset(info, 0, sizeof(*info));
	for (line = strtok_r(data, "\n", &save); line != NULL;
	     line = strtok_r(NULL, "\n", &save)) {
		if (strncmp(line, "clientid: 0x", 12) == 0) {
			char *end;
			unsigned long long value;

			if (seen_clientid++)
				goto malformed;
			errno = 0;
			value = strtoull(line + 12, &end, 16);
			if (errno != 0 || end == line + 12 || *end != '\0')
				goto malformed;
			info->clientid = (uint64_t)value;
		} else if (strncmp(line, "status: ", 8) == 0) {
			if (seen_status++)
				goto malformed;
			info->confirmed = strcmp(line + 8, "confirmed") == 0;
		} else if (strncmp(line, "name: ", 6) == 0) {
			size_t len = strlen(line + 6);

			if (seen_name++ || len >= sizeof(info->name))
				goto malformed;
			memcpy(info->name, line + 6, len + 1u);
		} else if (strncmp(line, "minor version: ", 15) == 0) {
			char *end;
			unsigned long value;

			if (seen_minor++)
				goto malformed;
			errno = 0;
			value = strtoul(line + 15, &end, 10);
			if (errno != 0 || end == line + 15 || *end != '\0' ||
			    value > UINT32_MAX)
				goto malformed;
			info->minor_version = (uint32_t)value;
		} else if (strncmp(line, "session slots:", 14) == 0) {
			if (seen_sessions++ ||
			    parse_sessions(line + 14, &info->session_count) != 0)
				goto malformed;
		}
	}
	if (seen_clientid != 1u || seen_status != 1u || seen_name != 1u ||
	    seen_minor != 1u || seen_sessions != 1u)
		goto malformed;
	return 0;

malformed:
	errno = EPROTO;
	return -1;
}

static int read_client_info(int client_fd, struct client_info *info)
{
	char data[INFO_MAX + 1u];
	int fd, rc, saved;

	fd = openat(client_fd, "info", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	rc = read_info(fd, data);
	saved = errno;
	if (close(fd) != 0 && rc == 0) {
		rc = -1;
		saved = errno;
	}
	if (rc == 0) {
		rc = parse_info(data, info);
		saved = errno;
	}
	errno = saved;
	return rc;
}

int nfsp_lifecycle_expire(const char *clients_dir, uint32_t lane,
			  uint32_t client, struct nfsp_lifecycle_result *result)
{
	char expected[160], hostname[HOST_NAME_MAX + 1u];
	DIR *directory = NULL;
	struct dirent *entry;
	int clients_fd = -1, selected_fd = -1;
	unsigned matched_owner = 0, matched_confirmed = 0;
	struct client_info selected = {0};
	int rc = -1, saved = 0;

	if (clients_dir == NULL || result == NULL || lane > 255u || client > 1u) {
		errno = EINVAL;
		return -1;
	}
	memset(result, 0, sizeof(*result));
	result->client = client;
	memset(hostname, 0, sizeof(hostname));
	if (gethostname(hostname, sizeof(hostname) - 1u) != 0 ||
	    !safe_hostname(hostname)) {
		errno = EINVAL;
		return -1;
	}
	if (snprintf(expected, sizeof(expected),
		     "\"Linux NFSv4.1 frozen-phase9-lane%" PRIu32
		     "-client%" PRIu32 "/%s\"", lane, client, hostname) >=
	    (int)sizeof(expected)) {
		errno = EOVERFLOW;
		return -1;
	}
	clients_fd = open(clients_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
			  O_NOFOLLOW);
	if (clients_fd < 0)
		return -1;
	directory = fdopendir(dup(clients_fd));
	if (directory == NULL)
		goto out;
	for (;;) {
		struct client_info info;
		int client_fd;

		errno = 0;
		entry = readdir(directory);
		if (entry == NULL) {
			if (errno != 0)
				goto out;
			break;
		}
		if (!numeric_name(entry->d_name))
			continue;
		client_fd = openat(clients_fd, entry->d_name,
				   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (client_fd < 0) {
			if (errno == ENOENT)
				continue;
			goto out;
		}
		if (read_client_info(client_fd, &info) != 0) {
			saved = errno;
			close(client_fd);
			errno = saved;
			if (saved == ENOENT || saved == ENXIO)
				continue;
			goto out;
		}
		if (strcmp(info.name, expected) != 0 || info.minor_version != 1u) {
			close(client_fd);
			continue;
		}
		matched_owner++;
		if (!info.confirmed) {
			close(client_fd);
			continue;
		}
		matched_confirmed++;
		if (matched_confirmed == 1u) {
			selected_fd = client_fd;
			selected = info;
		} else {
			close(client_fd);
		}
	}
	if (matched_confirmed > 1u) {
		errno = EEXIST;
		goto out;
	}
	if (matched_confirmed == 0u) {
		errno = matched_owner == 0u ? ENOENT : EAGAIN;
		goto out;
	}
	if (selected.session_count == 0u) {
		errno = ENODATA;
		goto out;
	}
	{
		static const char command[] = "expire\n";
		int ctl = openat(selected_fd, "ctl",
				 O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
		ssize_t written;

		if (ctl < 0)
			goto out;
		do {
			written = write(ctl, command, sizeof(command) - 1u);
		} while (written < 0 && errno == EINTR);
		saved = errno;
		if (close(ctl) != 0 && written == (ssize_t)(sizeof(command) - 1u)) {
			written = -1;
			saved = errno;
		}
		if (written != (ssize_t)(sizeof(command) - 1u)) {
			errno = written < 0 ? saved : EIO;
			goto out;
		}
	}
	result->minor_version = selected.minor_version;
	result->session_count = selected.session_count;
	result->clientid = selected.clientid;
	rc = 0;

out:
	saved = errno;
	if (selected_fd >= 0)
		close(selected_fd);
	if (directory != NULL)
		closedir(directory);
	if (clients_fd >= 0)
		close(clients_fd);
	errno = saved;
	return rc;
}

static int open_listener(const char *path)
{
	struct sockaddr_un address;
	int fd;

	if (path == NULL || strlen(path) >= sizeof(address.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, path);
	unlink(path);
	if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
	    chmod(path, 0600) != 0 || listen(fd, 32) != 0) {
		int saved = errno;

		close(fd);
		unlink(path);
		errno = saved;
		return -1;
	}
	return fd;
}

static void reply_packet(uint8_t reply[NFSP_LIFECYCLE_REPLY_LEN],
			 uint32_t status,
			 const struct nfsp_lifecycle_result *result)
{
	memset(reply, 0, NFSP_LIFECYCLE_REPLY_LEN);
	memcpy(reply, NFSP_LIFECYCLE_REPLY_MAGIC, 8);
	put32(reply + 8, status);
	put32(reply + 12, result->client);
	put32(reply + 16, result->minor_version);
	put32(reply + 20, result->session_count);
	put64(reply + 24, result->clientid);
}

static void serve_one(int listener, const char *clients_dir, uint32_t lane)
{
	uint8_t request[NFSP_LIFECYCLE_REQUEST_LEN + 1u];
	uint8_t reply[NFSP_LIFECYCLE_REPLY_LEN];
	struct nfsp_lifecycle_result result = {0};
	struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
	uint32_t operation = 0, status = EPROTO;
	int fd = accept(listener, NULL, NULL);
	ssize_t n;

	if (fd < 0)
		return;
	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	n = recv(fd, request, sizeof(request), 0);
	if (n == (ssize_t)NFSP_LIFECYCLE_REQUEST_LEN &&
	    memcmp(request, NFSP_LIFECYCLE_REQUEST_MAGIC, 8) == 0) {
		operation = get32(request + 8);
		result.client = get32(request + 12);
		if (operation != NFSP_LIFECYCLE_OP_EXPIRE) {
			status = EOPNOTSUPP;
		} else if (result.client > 1u) {
			status = EINVAL;
		} else if (nfsp_lifecycle_expire(clients_dir, lane, result.client,
						 &result) == 0) {
			status = 0;
		} else {
			status = (uint32_t)errno;
		}
	}
	reply_packet(reply, status, &result);
	(void)send(fd, reply, sizeof(reply), MSG_NOSIGNAL);
	printf("lifecycle request lane=%" PRIu32 " op=%" PRIu32
	       " client=%" PRIu32 " status=%" PRIu32 " clientid=0x%016" PRIx64
	       " minor=%" PRIu32 " sessions=%" PRIu32 "\n",
	       lane, operation, result.client, status, result.clientid,
	       result.minor_version, result.session_count);
	fflush(stdout);
	close(fd);
}

int nfsp_lifecycle_serve(const char *socket_path, const char *clients_dir,
			 uint32_t lane, const _Atomic int *stop)
{
	struct pollfd pollfd;
	int listener, rc = 0, saved;

	if (stop == NULL || lane > 255u) {
		errno = EINVAL;
		return -1;
	}
	listener = open_listener(socket_path);
	if (listener < 0)
		return -1;
	printf("lifecycle ready: lane=%" PRIu32 " path=%s\n", lane, socket_path);
	fflush(stdout);
	pollfd.fd = listener;
	pollfd.events = POLLIN;
	while (!atomic_load(stop)) {
		int polled = poll(&pollfd, 1, 200);

		if (polled < 0) {
			if (errno == EINTR)
				continue;
			rc = -1;
			break;
		}
		if (polled > 0 && (pollfd.revents & POLLIN) != 0)
			serve_one(listener, clients_dir, lane);
		if ((pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
			errno = EIO;
			rc = -1;
			break;
		}
	}
	saved = errno;
	close(listener);
	unlink(socket_path);
	errno = saved;
	return rc;
}
