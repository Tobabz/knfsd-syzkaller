/* Publish an opt-in client-facing NLM TCP port in this namespace's rpcbind. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netconfig.h>
#include <rpc/rpcb_clnt.h>
#include <stdio.h>
#include <stdlib.h>

#define NLM_PROGRAM 100021

int main(int argc, char **argv)
{
    struct netconfig *tcp;
    struct sockaddr_in address = {.sin_family = AF_INET};
    struct netbuf netbuf = {.buf = &address, .len = sizeof(address),
                            .maxlen = sizeof(address)};
    char *end;
    unsigned long port;
    int version;

    if (argc != 2) {
        fprintf(stderr, "usage: %s FRONT_PORT\n", argv[0]);
        return 2;
    }
    errno = 0;
    port = strtoul(argv[1], &end, 10);
    if (errno || end == argv[1] || *end || port == 0 || port > 65535) {
        fprintf(stderr, "invalid front port\n");
        return 2;
    }
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    tcp = getnetconfigent("tcp");
    if (!tcp) {
        fprintf(stderr, "tcp netconfig missing\n");
        return 1;
    }
    for (version = 1; version <= 4; version += version == 1 ? 2 : 1) {
        if (!rpcb_unset(NLM_PROGRAM, (rpcvers_t)version, tcp) ||
            !rpcb_set(NLM_PROGRAM, (rpcvers_t)version, tcp, &netbuf)) {
            fprintf(stderr, "failed to publish NLMv%d TCP port %lu\n",
                    version, port);
            freenetconfigent(tcp);
            return 1;
        }
    }
    freenetconfigent(tcp);
    return 0;
}
