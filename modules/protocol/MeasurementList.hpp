/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#ifndef SEDIMENT_MODULES_PROTOCOL_MEASUREMENTLIST_HPP_
#define SEDIMENT_MODULES_PROTOCOL_MEASUREMENTLIST_HPP_

#include <vector>

#include "Measurement.hpp"

#define MEAS_LIST_LEN 1

class MeasurementList
{
private:
    vector<Measurement> list;

public:
    MeasurementList(){ }

    uint32_t getSize();
    string toString();
    void decode(Vector &data);
    void encode(Vector &data);

    void add(MeasurementType type, uint32_t elapsedTime, uint32_t optional)
    {
        Measurement measurement(type, elapsedTime, optional);

        list.push_back(measurement);
    }

    vector<Measurement> &getList()
    {
        return list;
    }
};

#endif /* SEDIMENT_MODULES_PROTOCOL_MEASUREMENTLIST_HPP_ */
