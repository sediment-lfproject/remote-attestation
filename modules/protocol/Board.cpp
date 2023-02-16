/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "sediment.h"

#include "Board.hpp"

using namespace std;

uint32_t Board::getTemperature()
{
    static uint32_t temp = 25000;

    temp += (rand() % 2000) - 1000;

    return (int32_t) temp;
}

uint32_t Board::getHumidity()
{
    static uint32_t humidity = 40000;

    humidity += (rand() % 2000) - 1000;

    return (int32_t) humidity;
}
