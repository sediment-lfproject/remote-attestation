/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#pragma once

#include "Config.hpp"

using namespace std;

class Comm
{
public:

    static int setup(int port);
    static int connectTcp(Endpoint *endpoint);
};
