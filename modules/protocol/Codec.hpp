/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <vector>
#include <string>

#include "sediment.h"
#include "Vector.hpp"

using namespace std;

class Codec
{
private:

public:
    static int getInt(Vector &data, int len);
    static void putInt(int value, Vector &data, int len);

    static void putString(Vector &data, string &src);
    static void getString(Vector &data, int stringLen, string &dst);

    static void putByteArray(Vector &data, vector<uint8_t> &src);
    static void getByteArray(Vector &data, int stringLen, vector<uint8_t> &dst);

    static void putByteArray(Vector &data, Vector &src);
    static void getByteArray(Vector &data, int stringLen, Vector &dst);
};
