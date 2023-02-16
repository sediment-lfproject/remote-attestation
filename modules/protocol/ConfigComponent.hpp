/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
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
    Endpoint *aService  = NULL; // verifier attestation service
    Endpoint *outgoing2 = NULL;

public:
    ConfigComponent()
    { }

    string toString()
    {
        return SD_TO_STRING(
            "id: " + id + "\n"
            + "\tincoming: " + (incoming == NULL ? "" : incoming->toStringOneline()) + "\n"
            + "\toutgoing: " + (outgoing == NULL ? "" : outgoing->toStringOneline()) + "\n"
            + "\toutgoing2: " + (outgoing2 == NULL ? "" : outgoing2->toStringOneline()) + "\n"
            + "\taService: " + (aService == NULL ? "" : aService->toStringOneline()) + "\n");
    }

    Endpoint * getIncoming()
    {
        return incoming;
    }

    Endpoint * getOutgoing()
    {
        return outgoing;
    }

    Endpoint * getOutgoing2()
    {
        return outgoing2;
    }

    Endpoint * getAService()
    {
        return aService;
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

    void setAService(Endpoint *aService)
    {
        this->aService = aService;
    }

    void setIncoming(Endpoint *incoming)
    {
        this->incoming = incoming;
    }

    void setOutgoing2(Endpoint *outgoing2)
    {
        this->outgoing2 = outgoing2;
    }
};
