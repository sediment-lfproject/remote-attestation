/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "MeasurementList.hpp"
#include "Log.hpp"

uint32_t MeasurementList::getSize()
{
    int sz = 0;

    for (uint32_t i = 0; i < list.size(); i++)
        sz += list[i].getSize();

    return MEAS_LIST_LEN + sz;
}

string MeasurementList::toString()
{
    string str;

    for (uint32_t i = 0; i < list.size(); i++)
        str += list[i].toString();

    return SD_TO_STRING(str);
}

void MeasurementList::decode(Vector &data)
{
    uint32_t numMeas = Codec::getInt(data, MEAS_LIST_LEN);

    list.resize(numMeas);
    for (uint32_t i = 0; i < numMeas; i++) {
        list[i].decode(data);
    }
}

void MeasurementList::encode(Vector &data)
{
    Codec::putInt(list.size(), data, MEAS_LIST_LEN);
    for (uint32_t i = 0; i < list.size(); i++) {
        list[i].encode(data);
    }
}
