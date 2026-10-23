/* Set or inspect this network namespace's lockd TCP listener port. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* include/uapi/linux/lockd_netlink.h in the pinned kernel. */
#define LOCKD_FAMILY "lockd"
#define LOCKD_A_SERVER_TCP_PORT 2
#define LOCKD_CMD_SERVER_SET 1
#define LOCKD_CMD_SERVER_GET 2
#define ATTR_HEADER_LEN 4u

static int append_attr(struct nlmsghdr *message, size_t capacity,
                       uint16_t type, const void *data, size_t length)
{
    size_t old = NLMSG_ALIGN(message->nlmsg_len);
    size_t total = ATTR_HEADER_LEN + length;
    size_t next = old + (size_t)NLA_ALIGN((int)total);
    struct nlattr *attr;
    if (total > UINT16_MAX || total > INT32_MAX || next > capacity)
        return -1;
    attr = (struct nlattr *)((char *)message + old);
    attr->nla_type = type;
    attr->nla_len = (uint16_t)total;
    memcpy((char *)attr + ATTR_HEADER_LEN, data, length);
    memset((char *)attr + total, 0, next - old - total);
    message->nlmsg_len = (uint32_t)next;
    return 0;
}

static int transact(int fd, uint16_t family, uint8_t command, uint32_t seq,
                    const void *payload, size_t length, uint16_t request_type,
                    uint16_t answer_type, void *answer, size_t answer_len,
                    uint32_t grace)
{
    char request[256] = {0}, response[8192];
    struct nlmsghdr *header = (struct nlmsghdr *)request;
    struct genlmsghdr *generic = (struct genlmsghdr *)NLMSG_DATA(header);
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    struct sockaddr_nl sender;
    socklen_t sender_len;
    ssize_t count;

    header->nlmsg_len = NLMSG_LENGTH(sizeof(*generic));
    header->nlmsg_type = family;
    header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    header->nlmsg_seq = seq;
    generic->cmd = command;
    generic->version = family == GENL_ID_CTRL ? 2 : 1;
    if (payload != NULL && append_attr(header, sizeof(request), request_type,
                                       payload, length) != 0)
        return -1;
    if (command == LOCKD_CMD_SERVER_SET &&
        append_attr(header, sizeof(request), 1, &grace, sizeof(grace)) != 0)
        return -1;
    if (sendto(fd, request, header->nlmsg_len, 0,
               (const struct sockaddr *)&kernel, sizeof(kernel)) < 0)
        return -1;

    for (;;) {
        struct nlmsghdr *reply;
        unsigned remaining;
        sender_len = sizeof(sender);
        count = recvfrom(fd, response, sizeof(response), 0,
                         (struct sockaddr *)&sender, &sender_len);
        if (count <= 0) {
            if (count == 0)
                errno = EPIPE;
            return -1;
        }
        if (sender_len != sizeof(sender) || sender.nl_family != AF_NETLINK ||
            sender.nl_pid != 0) {
            errno = EPROTO;
            return -1;
        }
        remaining = (unsigned)count;
        for (reply = (struct nlmsghdr *)response;
             remaining >= sizeof(*reply) && reply->nlmsg_len >= sizeof(*reply) &&
             reply->nlmsg_len <= remaining; ) {
            struct genlmsghdr *body;
            struct nlattr *attr;
            unsigned attrs;
            unsigned step = NLMSG_ALIGN(reply->nlmsg_len);
            if (step > remaining) {
                errno = EPROTO;
                return -1;
            }
            if (reply->nlmsg_seq != seq)
                goto next_reply;
            if (reply->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *error = (const struct nlmsgerr *)NLMSG_DATA(reply);
                if (reply->nlmsg_len < NLMSG_LENGTH(sizeof(*error))) {
                    errno = EPROTO;
                    return -1;
                }
                if (error->error != 0) {
                    errno = -error->error;
                    return -1;
                }
                if (answer == NULL)
                    return 0;
                goto next_reply;
            }
            if (reply->nlmsg_len < NLMSG_LENGTH(sizeof(*body))) {
                errno = EPROTO;
                return -1;
            }
            body = (struct genlmsghdr *)NLMSG_DATA(reply);
            attrs = reply->nlmsg_len - (unsigned)NLMSG_LENGTH(sizeof(*body));
            for (attr = (struct nlattr *)((char *)body + GENL_HDRLEN);
                 attrs >= ATTR_HEADER_LEN && attr->nla_len >= ATTR_HEADER_LEN &&
                 (unsigned)NLA_ALIGN(attr->nla_len) <= attrs;
                 attrs -= (unsigned)NLA_ALIGN(attr->nla_len),
                 attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len))) {
                if ((attr->nla_type & NLA_TYPE_MASK) != answer_type ||
                    attr->nla_len != ATTR_HEADER_LEN + answer_len)
                    continue;
                memcpy(answer, (char *)attr + ATTR_HEADER_LEN, answer_len);
                return 0;
            }
            errno = EPROTO;
            return -1;
next_reply:
            remaining -= step;
            reply = (struct nlmsghdr *)((char *)reply + step);
        }
        if (remaining != 0) {
            errno = EPROTO;
            return -1;
        }
    }
}

int main(int argc, char **argv)
{
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    unsigned long requested = 0;
    uint16_t family = 0, port = 0;
    uint32_t grace = 0;
    char *end = NULL;
    int fd, status = 1;
    if (!((argc == 2 && strcmp(argv[1], "get") == 0) ||
          (argc == 3 && strcmp(argv[1], "set") == 0))) {
        fprintf(stderr, "usage: %s get | set PORT\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "set") == 0) {
        errno = 0;
        requested = strtoul(argv[2], &end, 10);
        if (end == argv[2] || *end != '\0' || requested == 0 ||
            requested > UINT16_MAX || errno == ERANGE) {
            fprintf(stderr, "invalid TCP port\n");
            return 2;
        }
    }
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0)
        goto out;
    struct timeval receive_timeout = {.tv_sec = 5};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
                   sizeof(receive_timeout)) != 0)
        goto out;
    if (transact(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1,
                 LOCKD_FAMILY, sizeof(LOCKD_FAMILY), CTRL_ATTR_FAMILY_NAME,
                 CTRL_ATTR_FAMILY_ID, &family, sizeof(family), 0) != 0 ||
        family == 0)
        goto out;
    if (requested != 0) {
        uint16_t new_port = (uint16_t)requested;
        if (transact(fd, family, LOCKD_CMD_SERVER_GET, 2, NULL, 0,
                     0, 1, &grace, sizeof(grace), 0) != 0 ||
            transact(fd, family, LOCKD_CMD_SERVER_SET, 3, &new_port,
                     sizeof(new_port), LOCKD_A_SERVER_TCP_PORT, 0, NULL, 0,
                     grace) != 0)
            goto out;
    }
    if (transact(fd, family, LOCKD_CMD_SERVER_GET, 4, NULL, 0,
                 0, LOCKD_A_SERVER_TCP_PORT, &port, sizeof(port), 0) != 0)
        goto out;
    if (requested != 0 && port != requested) {
        errno = EPROTO;
        goto out;
    }
    printf("%u\n", (unsigned)port);
    status = 0;
out:
    if (status != 0)
        perror("lockd netlink");
    if (fd >= 0)
        close(fd);
    return status;
}
