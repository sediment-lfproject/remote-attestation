/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "Endpoint.hpp"
#include "Crypto.hpp"
#include "Log.hpp"

uint32_t Endpoint::getSize()
{
    return PROTOCOL_LEN
           + ADDRESS_LEN
           + address.length()
           + PORT_LEN;
}

string Endpoint::toString()
{
    if (protocol == MIN_PROTOCOL)
        return "-";

    return SD_TO_STRING(
        "\nprotocol: " + TO_PROTOCOL(protocol)
        + "\naddress: " + address
        + "\nport: " + to_string(port));
}

string const Endpoint::toStringOneline() const
{
    if (protocol == MIN_PROTOCOL)
        return "";

    return SD_TO_STRING(
        TO_PROTOCOL(protocol) + ":" + address + ":" + to_string(port));
}

void Endpoint::decode(Vector &data)
{
    int cand = Codec::getInt(data, PROTOCOL_LEN);

    protocol = DECODE_CHECK(Protocol, cand, MIN_PROTOCOL, MAX_PROTOCOL, "bad protocol");

    int addressLen = Codec::getInt(data, ADDRESS_LEN);
    Codec::getString(data, addressLen, address);

    port = (uint16_t) Codec::getInt(data, PORT_LEN);
}

void Endpoint::encode(Vector &data)
{
    Codec::putInt(protocol, data, PROTOCOL_LEN);

    int addressLen = address.length();
    Codec::putInt(addressLen, data, ADDRESS_LEN);
    Codec::putString(data, address);

    Codec::putInt(port, data, PORT_LEN);
}

Protocol Endpoint::toProtocol(string &prot)
{
    if (prot.compare("tcp") == 0) {
        return TCP;
    }
    else if (prot.compare("udp") == 0) {
        return UDP;
    }
    else if (prot.compare("ble") == 0) {
        return BLUETOOTH;
    }
    else {
        SD_LOG(LOG_ERR, "unrecognized protocol %s", prot.c_str());
    }
    return MIN_PROTOCOL;
}
