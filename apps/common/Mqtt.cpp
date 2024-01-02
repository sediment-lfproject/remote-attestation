/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 *
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include <iostream>

#include "Prover.hpp"
#include "Board.hpp"
#include "Log.hpp"

/*
 * Run MQTT only, without SEDIMENT
 */
void Prover::runMqtt()
{
    string url = config.getMqttUrl();
    bool ok    = mqtt.connect(url, config.getComponent().getID());

    if (!ok) {
        return;
    }

    string id = config.getComponent().getID();
    while (true) {
        uint32_t ts         = (board != NULL) ? board->getTimestamp() : 0;
        uint64_t start_time = board->getTimeInstant();
        uint32_t elapsed    = board->getElapsedTime(start_time);

        const int message_size = config.getPayloadSize();
        char message[message_size];
        memset(message, '_', message_size); // pad the buffer

        int n = snprintf(message, message_size, "%d,%d,%s,", elapsed, ts, id.c_str());
        board->getAllSensors(board->getSeq(), message + n, message_size - n);
        message[message_size - 1] = '\0';

        mqtt.publish(message);

        board->incSeq();
        board->sleepSec(config.getReportInterval());
    }
    mqtt.disconnect();
}
