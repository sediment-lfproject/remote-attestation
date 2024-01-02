/*
 * Copyright (c) 2023-2024 Peraton Labs
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).
 */

#ifndef SEDIMENTUDF_HPP
#define SEDIMENTUDF_HPP

#include <string>

using namespace std;

class SedimentUDF {
protected:

public:
    SedimentUDF(){ }

    virtual ~SedimentUDF(){ }

    virtual std::string attest() const = 0;
};

typedef SedimentUDF * create_t();
typedef void destroy_t(SedimentUDF *);

#endif // ifndef SEDIMENTUDF_HPP
