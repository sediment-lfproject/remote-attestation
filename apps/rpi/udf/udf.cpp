/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 *
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */
#include "sediment_udf.hpp"
#include <cmath>
#include <string>

using namespace std;

/*
 * Each UDF{1,2,3}::attest() is expected to run the corresponding user defined function
 * and return a string starting with "OK" to indicate success; others for failure.
 * The substring following OK is ignored in the success case.
 */

class UDF1 : public SedimentUDF {
public:
    virtual string attest() const
    {
        const int BUF_SIZE = 256;
        char buf[BUF_SIZE];

        sprintf(buf, "/usr/local/nagios/libexec/check_procs -C rsyslogd -c 1: -u syslog");

        FILE *fp;
        if ((fp = popen(buf, "r")) == NULL) {
            printf("Error opening pipe!\n");
            return "bad 1";
        }

        while (fgets(buf, BUF_SIZE, fp) != NULL) { // TODO
            break;
        }

        if (pclose(fp)) {
            printf("Command not found or exited with error status\n");
        }
        string s(buf);

        return s;
    }
};

class UDF2 : public SedimentUDF {
public:
    virtual string attest() const
    {
        return "FAILED";
    }
};

class UDF3 : public SedimentUDF {
public:
    virtual string attest() const
    {
        return "FAILED";
    }
};


extern "C" SedimentUDF * create_udf1()
{
    return new UDF1;
}

extern "C" void destroy_udf1(SedimentUDF *p)
{
    delete p;
}

extern "C" SedimentUDF * create_udf2()
{
    return new UDF2;
}

extern "C" void destroy_udf2(SedimentUDF *p)
{
    delete p;
}

extern "C" SedimentUDF * create_udf3()
{
    return new UDF3;
}

extern "C" void destroy_udf3(SedimentUDF *p)
{
    delete p;
}
