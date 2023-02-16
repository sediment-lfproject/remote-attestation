/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#include "sediment.h"

#include "Codec.hpp"

#include "Message.hpp"
#include "Log.hpp"
#include "Vector.hpp"

using namespace std;

int Codec::getInt(Vector &data, int len)
{
    int index = data.getIndex();

    if (index >= data.getCapacity() || len > 4 || len < 0) {
        SD_LOG(LOG_ERR, "data too short: %d v.s. %d", index, data.getCapacity());
        return -1;
    }

    uint8_t *src = data.at(index);
    data.inc(len);

    if (len == 1)
        return *src;
    else if (len == 2) {
        uint16_t *si = (uint16_t *) src;
        return ntohs(*si);
    }
    else if (len == 4) {
        uint32_t *i = (uint32_t *) src;
        return ntohl(*i);
    }
    else {
        SD_LOG(LOG_ERR, "getInt: bad integer size %d", len);
        return -1;
    }
}

void Codec::putInt(int value, Vector &data, int len)
{
    if (len <= 0 || len > 4) {
        SD_LOG(LOG_ERR, "length out of range: (0, 32]: %d", len);
        return;
    }
    if (value > (1LL << len * 8) - 1) {
        SD_LOG(LOG_ERR, "value out of range: %d", value);
        data.inc(len);
        return;
    }

    int index    = data.getIndex();
    uint8_t *dst = data.at(index);

    data.inc(len);

    if (len == 1)
        *dst = (uint8_t) value;
    else if (len == 2) {
        uint16_t *si = (uint16_t *) dst;
        *si = htons(value);
    }
    else if (len == 4) {
        uint32_t *i = (uint32_t *) dst;
        *i = htonl(value);
    }
    else {
        SD_LOG(LOG_ERR, "putInt: bad integer size %d", len);
    }
}

bool enoughSpace(Vector data, int need)
{
    int remain = data.getCapacity() - data.getIndex();

    if (remain < need) {
        SD_LOG(LOG_ERR, "insufficient space: has %d, need %d", remain, need);
        return false;
    }
    return true;
}

void Codec::putString(Vector &data, string &src)
{
    if (!enoughSpace(data, src.size()))
        return;

    uint8_t *src_buf = (uint8_t *) &src[0];

    data.put(src_buf, src.size());
}

void Codec::getString(Vector &data, int stringLen, string &dst)
{
    if (!enoughSpace(data, stringLen))
        return;

    dst.resize(stringLen);
    uint8_t *dst_buf = (uint8_t *) &dst[0];

    data.get(dst_buf, stringLen);
}

void Codec::putByteArray(Vector &data, vector<uint8_t> &src)
{
    if (!enoughSpace(data, src.size()))
        return;

    uint8_t *src_buf = (uint8_t *) &src[0];

    data.put(src_buf, src.size());
}

void Codec::getByteArray(Vector &data, int stringLen, vector<uint8_t> &dst)
{
    if (!enoughSpace(data, dst.size()))
        return;

    dst.resize(stringLen);
    uint8_t *dst_buf = (uint8_t *) &dst[0];

    data.get(dst_buf, stringLen);
}

void Codec::putByteArray(Vector &data, Vector &src)
{
    if (!enoughSpace(data, src.size()))
        return;

    uint8_t *src_buf = (uint8_t *) src.at(0);

    data.put(src_buf, src.size());
}

void Codec::getByteArray(Vector &data, int stringLen, Vector &dst)
{
    if (!enoughSpace(data, stringLen))
        return;

    dst.resize(stringLen);
    uint8_t *dst_buf = (uint8_t *) dst.at(0);

    data.get(dst_buf, stringLen);
    dst.inc(stringLen);
}
