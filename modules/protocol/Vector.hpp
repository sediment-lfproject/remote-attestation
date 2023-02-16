/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <cstdlib>
#include <cstring>

// #include "Log.hpp"

using namespace std;

class Vector
{
private:
    int index       = 0; // the next index of buffer to be stored at or retrieve from
    int capacity    = 0; // total number bytes in buffer
    uint8_t *buffer = NULL;

public:
    Vector()
    { }

    Vector(const Vector &src)
    {
        copy(src);
    }

    Vector(int capacity)
    {
        this->index    = 0;
        this->capacity = capacity;
        buffer         = (uint8_t *) malloc(capacity);
    }

    Vector(uint8_t *src, int capacity) : Vector(capacity)
    {
        memcpy(buffer, src, capacity);
    }

    ~Vector()
    {
        if (buffer != NULL) {
            free(buffer);
        }
    }

    void copy(const Vector &src)
    {
        this->index    = src.index;
        this->capacity = src.capacity;
        if (buffer != NULL)
            free(buffer);
        buffer = (uint8_t *) malloc(src.capacity);
        memcpy(buffer, src.buffer, capacity);
    }

    void inc(int lenInBytes)
    {
        index += lenInBytes;
    }

    void resize(int size)
    {
        uint8_t *old_buffer = buffer;
        int old_capacity    = capacity;

        buffer   = (uint8_t *) malloc(size);
        capacity = size;

        if (old_buffer != NULL) {
            int cap = (capacity > old_capacity) ? old_capacity : capacity;
            memcpy(buffer, old_buffer, cap);
            free(old_buffer);
        }
    }

    int getCapacity()
    {
        return capacity;
    }

    int size()
    {
        return index;
    }

    int getIndex() const
    {
        return index;
    }

    void reset()
    {
        memset(buffer, '\0', capacity);
        index = 0;
    }

    void reset(char val)
    {
        memset(buffer, val, index);
    }

    uint8_t * at(int index)
    {
        return &buffer[index];
    }

    // note side effect of updating index
    void get(uint8_t *dst, int len)
    {
        if (index + len > capacity) {
            //            SD_LOG(LOG_ERR, "get: vector overflow: %d v.s. %d", index + len, capacity);
            return;
        }
        char *src = (char *) buffer + index;
        memcpy(dst, src, len);

        index += len;
    }

    // note side effect of updating index
    void put(uint8_t *src, int len)
    {
        if (index + len > capacity) {
            //            SD_LOG(LOG_ERR, "set: Vector overflow: %d v.s. %d", index + len, capacity);
            return;
        }
        char *dst = (char *) buffer + index;
        memcpy(dst, src, len);

        index += len;
    }
};
