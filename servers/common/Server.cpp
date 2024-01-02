/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <iostream>
#include <sstream>
#include <thread>

#include "nv.h"
#include "sediment.h"

#include "Server.hpp"
#include "EndpointSock.hpp"
#include "Comm.hpp"
#include "Device.hpp"
#include "Utils.hpp"
#include "Log.hpp"

#define MESSAGE_BUF_SIZE 32000

using namespace std;

void Server::run()
{
    int port = endpoint.getPort();

    int server_fd = Comm::setup(port);

    if (server_fd < 0) {
        SD_LOG(LOG_ERR, "control: socket cannot be created.");
        return;
    }

    struct timeval tv;
    tv.tv_sec  = 60; // in seconds
    tv.tv_usec = 0;

    struct sockaddr_in client;

    while (1) {
        socklen_t client_len = sizeof(client);
        int sock = accept(server_fd, (struct sockaddr *) &client, &client_len);
        if (sock == -1) {
            SD_LOG(LOG_ERR, "accept failed: %s, sleeping for 5 seconds", strerror(errno));
            sleep(5);
            continue;
        }
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, str, INET_ADDRSTRLEN);
        SD_LOG(LOG_DEBUG, "accept socket %d: %s:%d", sock, str, client.sin_port);

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof tv)) {
            SD_LOG(LOG_ERR, "failed to set timeout on socket %d: %s", sock, strerror(errno));
        }

        string clientAddr(str);
        EndpointSock *epSock = new EndpointSock(endpoint.getProtocol(), clientAddr, client.sin_port, sock);

        std::unique_ptr<DeviceManager> deviceManager = std::make_unique<DeviceManager>(dbType, dbName);
        if (deviceManager->isConnected()) {
            std::thread conn(&Server::runProcedure, this, epSock, std::move(deviceManager));
            conn.detach();
        }
        else {
            close(sock);
        }
    }
}

void Server::runProcedure(EndpointSock *epSock, std::unique_ptr<DeviceManager> deviceManager)
{
    int peer_sock = epSock->getSock();

    uint8_t buf[MESSAGE_BUF_SIZE];
    int timeOutCount = 0;
    int expected     = 0;
    int received     = 0;
    char *ptr        = (char *) buf;
    int avail        = MESSAGE_BUF_SIZE;

    while (true) {
        int bytesRead = recv(peer_sock, ptr, avail, 0);
        if (bytesRead < 0) {
            if (errno == EAGAIN) {
                SD_LOG(LOG_ERR, "socket timeout %d %s", errno, strerror(errno));
                timeOutCount++;
                if (timeOutCount < MAX_TIME_OUT)
                    continue;
                else
                    break;
            }
            else
                break;
        }
        else if (bytesRead == 0) {
            break;
        }
        if (bytesRead >= 2) {
            if (expected == 0) {
                uint32_t hb = buf[0];
                uint32_t lb = buf[1];
                expected = hb << 8 | lb;
            }
        }
        received += bytesRead;
        if (received < expected) {
            ptr   += bytesRead;
            avail -= bytesRead;
            continue;
        }

        Message *message = decodeMessage(buf, expected);
        if (message == NULL) {
            break;
        }
        SD_LOG(LOG_DEBUG, "received.....%s", message->toString().c_str());

        Device *device = authenticate(*deviceManager, message, buf, expected);
        if (device == NULL) {
            delete message;
            break;
        }

        Message *response = handleMessage(*deviceManager, message, epSock, device, buf, expected);
        delete message; // message handled, no longer needed

        if (response != NULL) {
            finalizeAndSend(*deviceManager, peer_sock, response);
            delete response; // response sent, no longer needed
        }
        else
            break;

        received = 0;
        expected = 0;
        ptr      = (char *) buf;
        avail    = MESSAGE_BUF_SIZE;
    }
    delete epSock;
    SD_LOG(LOG_DEBUG, "close socket %d", peer_sock);
    close(peer_sock);
}

time_t Server::getTimestamp()
{
    long ms;  // Milliseconds
    time_t s; // Seconds
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);

    s  = spec.tv_sec;
    ms = round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
    if (ms > 999) {
        s++;
        ms = 0;
    }
    return s;
}

void Server::setTimestamp(Message *message)
{
    message->setTimestamp(getTimestamp());
}

void Server::finalizeAndSend(DeviceManager &deviceManager, int peer_sock, Message *message)
{
    setTimestamp(message);
    AuthToken &authToken = message->getAuthToken();

    uint32_t msg_len;
    uint8_t *serialized = message->serialize(&msg_len);

    calAuthToken(deviceManager, message, serialized, msg_len);

    uint32_t size = authToken.getSize();
    Vector data(size);
    authToken.encode(data);

    memcpy(serialized + AUTH_TOKEN_OFFSET, (char *) data.at(0), authToken.getSize());

    sendMessage(peer_sock, message->getId(), serialized, msg_len);
    free(serialized);

    SD_LOG(LOG_DEBUG, "sent (%d).........%s", msg_len, message->toString().c_str());
}

void Server::calAuthToken(DeviceManager &deviceManager, Message *message, uint8_t *serialized, uint32_t len)
{
    // TODO
    (void) serialized;
    (void) len;
    Seec *seec = findSeec(deviceManager, message->getDeviceID());
    if (seec == NULL) {
        SD_LOG(LOG_ERR, "null seec, auth digest not calculated");
        return;
    }

    Crypto *crypto = seec->getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "null crypto, auth digest not calculated");
        return;
    }

    AuthToken &authToken = message->getAuthToken();
    crypto->calDigest(authToken, serialized, len, message->getPayloadOffset());
}

Device * Server::authenticate(DeviceManager &deviceManager, Message *message, uint8_t *serialized, uint32_t len)
{
    (void) serialized;
    (void) len;
    string &deviceID = message->getDeviceID();
    Device *device   = deviceManager.findDevice(deviceID);
    if (device == NULL) {
        SD_LOG(LOG_ERR, "unknown device %s", deviceID.c_str());
        return NULL;
    }

    Seec *seec = device->getSeec();
    if (seec == NULL) {
        SD_LOG(LOG_ERR, "seec not found for device %s", deviceID.c_str());
        return NULL;
    }

    if (!config.isAuthenticationEnabled()) {
        SD_LOG(LOG_WARNING, "authentication disabled");
        return device;

        ;
    }

    Crypto *crypto = seec->getCrypto();
    if (crypto == NULL) {
        SD_LOG(LOG_ERR, "crypto not found for device %s", deviceID.c_str());
        return NULL;
    }

    return crypto->authenticate(message->getAuthToken(), serialized, len, message->getPayloadOffset()) ? device : NULL;
}

Seec * Server::findSeec(DeviceManager &deviceManager, string deviceID)
{
    Device *device = deviceManager.findDevice(deviceID);

    if (device == NULL) {
        SD_LOG(LOG_ERR, "unknown device %s", deviceID.c_str());
        return NULL;
    }

    return device->getSeec();
}

void Server::handlePubData(char *data)
{
    (void) data;
}
