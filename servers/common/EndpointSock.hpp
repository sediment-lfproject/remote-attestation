/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include "Endpoint.hpp"

using namespace std;

class EndpointSock : public Endpoint
{
protected:
    int sock = -1;
    string name;

public:
    EndpointSock()
    { }

    EndpointSock(Protocol protocol, string addr, int port, int sock) :
        Endpoint(protocol, addr, port)
    {
        this->sock = sock;
    }

    EndpointSock(const string &name, Protocol protocol, string addr, int port) :
        Endpoint(protocol, addr, port)
    {
        this->name = name;
    }

    EndpointSock(const EndpointSock &endpoint) : Endpoint(endpoint)
    {
        this->name = endpoint.name;
        this->sock = endpoint.sock;
    }

    //    virtual ~EndpointSock() {}

    bool operator == (EndpointSock &that)
    {
        return (protocol == that.protocol &&
               !address.compare(that.address) &&
               port == that.port);
    }

    string toString()
    {
        const int LEN = 50;

        char send[LEN];

        snprintf(send, LEN, "%-18s %s:%d", name.c_str(), address.c_str(), port);
        string srcEnd(send);

        return srcEnd;
    }

    virtual ~EndpointSock()
    {
        if (sock) {
            SD_LOG(LOG_DEBUG, "close socket %d", sock);
            close(sock);
        }
    }

    int getSock() const
    {
        return sock;
    }

    void setSock(int sock = -1)
    {
        this->sock = sock;
    }

    const string& getName() const
    {
        return name;
    }

    void setName(const string &name)
    {
        this->name = name;
    }
};
