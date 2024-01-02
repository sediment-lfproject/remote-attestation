/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#include "Measurement.hpp"
#include "Log.hpp"

uint32_t Measurement::getSize()
{
    return MEAS_TYPE_LEN
           + ELAPSED_TIME_LEN
           + OPTIONAL_LEN;
}

string Measurement::toString()
{
    return
          "\nelapsedTime: " + TO_MEAS_TYPE(type) + " "
        + to_string(elapsedTime) + " us, optional:" + to_string(optional);
}

void Measurement::decode(Vector &data)
{
    int cand = Codec::getInt(data, MEAS_TYPE_LEN);

    type = DECODE_CHECK(MeasurementType, cand, MIN_MEASUREMENT, MAX_MEASUREMENT, "bad measurement type");

    elapsedTime = Codec::getInt(data, ELAPSED_TIME_LEN);
    optional    = Codec::getInt(data, OPTIONAL_LEN);
}

void Measurement::encode(Vector &data)
{
    Codec::putInt(type, data, MEAS_TYPE_LEN);
    Codec::putInt(elapsedTime, data, ELAPSED_TIME_LEN);
    Codec::putInt(optional, data, OPTIONAL_LEN);
}
