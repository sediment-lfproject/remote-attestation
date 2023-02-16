/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 */

#include <iostream>

#include "Prover.hpp"
#include "Board.hpp"
#include "Log.hpp"

void Prover::runMqtt()
{
    string url = endpoint.getAddress();
    bool ok    = mqtt.connect(url, config.getComponent().getID());

    if (!ok) {
        return;
    }

    string id = config.getComponent().getID();
    while (true) {
        uint32_t ts         = (board != NULL) ? board->getTimestamp() : 0;
        uint64_t start_time = board->getTimeInstant();
        uint32_t temp       = board->getTemperature();
        uint32_t humid      = board->getHumidity();
        uint32_t elapsed    = board->getElapsedTime(start_time);

        const int message_size = config.getPayloadSize();
        char message[message_size];
        memset(message, '_', message_size); // pad the buffer
        int n = snprintf(message, message_size, "%d,%d,%s,%d,%d,%d",
            elapsed, ts, id.c_str(), board->getSeq(), temp, humid);
        message[message_size - 1] = '\0';
        message[n] = '_';

        mqtt.publish(message);

        board->incSeq();
        board->sleepSec(config.getReportInterval());
    }
    mqtt.disconnect();
}
