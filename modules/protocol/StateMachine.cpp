/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "sediment.h"

#include "StateMachine.hpp"
#include "Log.hpp"

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

using namespace std;

bool StateMachine::sendMessage(int peer_sock, MessageID messageID, uint8_t *serialized, uint32_t msg_len)
{
    if (serialized == NULL) {
        SD_LOG(LOG_ERR, "failed to serialize message");
        return false;
    }
    if (config.getTransport() == TRANSPORT_SEDIMENT_MQTT &&
      messageID == DATA)
    {
        string pub = Log::toHexNoLimit((char *) serialized, msg_len);
        mqtt.publish((char *) &pub[0]);
    }
    else {
        int sent     = 0;
        int remain   = msg_len;
        uint8_t *ptr = serialized;
        while (remain > 0) {
            int bytes = send(peer_sock, (const char *) ptr, remain, MSG_NOSIGNAL);
            if (bytes == EPIPE) {
                SD_LOG(LOG_ERR, "broken send pipe: %s", Log::toMessageID(messageID).c_str());
                free(serialized);
                return false;
            }
            ptr    += bytes;
            sent   += bytes;
            remain -= bytes;
        }
    }
    return true;
}

void StateMachine::finalizeAndSend(int peer_sock, Message *message)
{
    setTimestamp(message);
    AuthToken &authToken = message->getAuthToken();

    uint32_t msg_len;
    uint8_t *serialized = message->serialize(&msg_len);

    calAuthToken(message, serialized, msg_len);

    uint32_t size = authToken.getSize();
    Vector data(size);
    authToken.encode(data);

    memcpy(serialized + AUTH_TOKEN_OFFSET, (char *) data.at(0), authToken.getSize());

    sendMessage(peer_sock, message->getId(), serialized, msg_len);
    free(serialized);

    SD_LOG(LOG_DEBUG, "sent (%d).........%s", msg_len, message->toString().c_str());
}

bool StateMachine::isWellFormed(uint8_t dataArray[], uint32_t len)
{
    if (len < MIN_MSG_LEN) {
        SD_LOG(LOG_ERR, "message too short: %d, minimum length %d", len, MIN_MSG_LEN);
        return false;
    }

    if (len > MAX_MSG_LEN) {
        SD_LOG(LOG_ERR, "message too long: %d, max length %d", len, MAX_MSG_LEN);
        return false;
    }

    MessageID id = (MessageID) dataArray[MESSAGE_ID_OFFSET];
    if (id <= MIN_MSG_ID || id >= MAX_MSG_ID) {
        SD_LOG(LOG_ERR, "invalid message id: %d", id);
        return false;
    }

    return true;
}
