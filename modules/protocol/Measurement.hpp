/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#ifndef SEDIMENT_MODULES_PROTOCOL_MEASUREMENT_HPP_
#define SEDIMENT_MODULES_PROTOCOL_MEASUREMENT_HPP_

#include <string>

#include "Enum.hpp"
#include "Vector.hpp"
#include "Codec.hpp"

#define MEAS_TYPE_LEN    1
#define ELAPSED_TIME_LEN 4
#define OPTIONAL_LEN     4

class Measurement
{
private:
    MeasurementType type;
    uint32_t elapsedTime;
    int optional;

public:
    Measurement(){ }

    Measurement(MeasurementType type, uint32_t elapsedTime, int optional)
    {
        this->type        = type;
        this->elapsedTime = elapsedTime;
        this->optional    = optional;
    }

    uint32_t getSize();
    string toString();
    void decode(Vector &data);
    void encode(Vector &data);

    int getElapsedTime() const
    {
        return elapsedTime;
    }

    void setElapsedTime(uint32_t elapsedTime)
    {
        this->elapsedTime = elapsedTime;
    }

    MeasurementType getType() const
    {
        return type;
    }

    void setType(MeasurementType type)
    {
        this->type = type;
    }

    int getOptional() const
    {
        return optional;
    }

    void setOptional(int optional)
    {
        this->optional = optional;
    }
};

#endif /* SEDIMENT_MODULES_PROTOCOL_MEASUREMENT_HPP_ */
