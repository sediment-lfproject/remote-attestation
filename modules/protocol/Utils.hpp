/*
 * Copyright (c) 2023 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * @author tchen
 */

#pragma once

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

// #include "Log.hpp"

using namespace std;

class Utils
{
private:

public:
    static inline void trim(std::string &s)
    {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));

        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), s.end());
    }

    static void readHex(vector<uint8_t> &vec, string hexString, int len)
    {
        char hex[3] = { '\0' };
        char *ptr   = (char *) &hexString[0];

        for (int i = 0; i < len; i++) {
            memcpy(hex, ptr, 2);
            uint8_t byte = (strtoul(hex, NULL, 16)) & 0xff;
            ptr += 2;

            vec.push_back(byte);
        }
        //
        // if ((int)vec.size() != len) {
        //     SD_LOG(LOG_ERR, "unexpected key length: %d v.s. %d", vec.size(), len);
        // }
    }

    static void readRsaKey(const string &keyFile, vector<uint8_t> &vec)
    {
        std::ifstream t(keyFile);
        std::stringstream buffer;

        buffer << t.rdbuf();

        // somehow whitespaces are stripped.
        //    copy(istream_iterator<uint8_t>(buffer), istream_iterator<uint8_t>(),
        //         back_inserter(vec));

        string str = buffer.str();
        vec.clear();
        for (int i = 0; i < (int) str.length(); i++)
            vec.push_back(str[i]);
        vec.push_back(0);
    }
};
