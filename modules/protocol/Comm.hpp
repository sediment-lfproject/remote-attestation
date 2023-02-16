/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
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
