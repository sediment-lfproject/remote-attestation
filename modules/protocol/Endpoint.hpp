/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <algorithm>

#include "Enum.hpp"
#include "Codec.hpp"
#include "Log.hpp"

#define PROTOCOL_LEN 1
#define ADDRESS_LEN  1
#define PORT_LEN     2

class Endpoint
{
protected:
    Protocol protocol = TCP;
    string address    = "192.168.0.166";
    int port = 8000;

public:
    Endpoint()
    {
        protocol = MIN_PROTOCOL;
    }

    Endpoint(Protocol protocol, string address, int port)
    {
        this->protocol = protocol;
        this->address  = address;
        this->port     = port;
    }

    Endpoint(string val)
    {
        // TODO: error checking
        string delimiter = ":";

        size_t colon1 = val.find(delimiter);
        string token  = val.substr(0, colon1);

        std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c){ return std::tolower(c); });

        protocol = toProtocol(token);

        val = val.substr(colon1 + 1);
        int colon2 = val.find(delimiter);
        address = val.substr(0, colon2);

        port = strtoul(val.substr(colon2 + 1).c_str(), NULL, 10);
    }

    Endpoint(const Endpoint &endpoint)
    {
        copy(endpoint);
    }

    void decode(Vector &data);
    void encode(Vector &data);

    uint32_t getSize();
    string toString();
    const string toStringOneline() const;

    static Protocol toProtocol(string &prot);

    void copy(const Endpoint &endpoint)
    {
        this->protocol = endpoint.protocol;
        this->address  = endpoint.address;
        this->port     = endpoint.port;
    }

    string getAddress() const
    {
        return address;
    }

    void setAddress(string address)
    {
        this->address = address;
    }

    int getPort() const
    {
        return port;
    }

    void setPort(int port)
    {
        this->port = port;
    }

    Protocol getProtocol() const
    {
        return protocol;
    }

    void setProtocol(Protocol protocol)
    {
        this->protocol = protocol;
    }
};
