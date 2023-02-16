/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "sediment.h"

#include "Comm.hpp"
#include "Log.hpp"

using namespace std;

int Comm::setup(int port)
{
    int server_fd, err;
    struct sockaddr_in server;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        SD_LOG(LOG_ERR, "Could not create socket");
        return -1;
    }

    server.sin_family      = AF_INET;
    server.sin_port        = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    int opt_val = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));

    err = bind(server_fd, (struct sockaddr *) &server, sizeof(server));
    if (err == -1) {
        SD_LOG(LOG_ERR, "Could not bind socket port %d", port);
        return -1;
    }

    err = listen(server_fd, 128);
    if (err == -1) {
        SD_LOG(LOG_ERR, "Could not listen on socket");
        return -1;
    }

    return server_fd;
}

int Comm::connectTcp(Endpoint *endpoint)
{
    const char *addr = &endpoint->getAddress().c_str()[0];
    int port         = endpoint->getPort();

    struct sockaddr_in remote_sock_addr;

    int client_sock;

    if ((client_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        SD_LOG(LOG_ERR, "TCP socket() failed");
        return -1;
    }
    struct timeval tv;
    tv.tv_sec  = 10; // in seconds
    tv.tv_usec = 0;

    if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof tv)) {
        SD_LOG(LOG_ERR, "failed to set timeout on socket %d: %s", client_sock, strerror(errno));
    }

    memset(&remote_sock_addr, 0, sizeof(remote_sock_addr));
    remote_sock_addr.sin_family = AF_INET;
    //    remote_sock_addr.sin_addr.s_addr = inet_addr(addr);
    remote_sock_addr.sin_port = htons(port);
    inet_pton(AF_INET, addr, &remote_sock_addr.sin_addr);

    if (connect(client_sock, (struct sockaddr *) &remote_sock_addr, sizeof(remote_sock_addr)) < 0) {
        SD_LOG(LOG_ERR, "connection failed: %s", endpoint->toStringOneline().c_str());
        close(client_sock);
        return -1;
    }

    return client_sock;
}
