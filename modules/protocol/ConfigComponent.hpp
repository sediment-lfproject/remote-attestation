/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include <fstream>

#include "Endpoint.hpp"
#include "Log.hpp"

using namespace std;

class ConfigComponent
{
private:
    string id = "Giant_Gecko";

    Endpoint *incoming  = NULL;
    Endpoint *outgoing  = NULL;
    Endpoint *revServer = NULL; // Revocation Server

public:
    ConfigComponent()
    { }

    string toString()
    {
        return
              "id: " + id + "\n"
            + "\tincoming: " + (incoming == NULL ? "" : incoming->toStringOneline()) + "\n"
            + "\toutgoing: " + (outgoing == NULL ? "" : outgoing->toStringOneline()) + "\n"
            + "\trevServer: " + (revServer == NULL ? "" : revServer->toStringOneline()) + "\n";
    }

    Endpoint * getIncoming()
    {
        return incoming;
    }

    Endpoint * getOutgoing()
    {
        return outgoing;
    }

    Endpoint * getRevServer()
    {
        return revServer;
    }

    string &getID()
    {
        return id;
    }

    void setOutgoing(Endpoint *outgoing = NULL)
    {
        this->outgoing = outgoing;
    }

    void setID(string id)
    {
        this->id = id;
    }

    void setIncoming(Endpoint *incoming)
    {
        this->incoming = incoming;
    }

    void setRevServer(Endpoint *revServer)
    {
        this->revServer = revServer;
    }
};
