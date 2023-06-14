#pragma once

#include "nv.h"

// This array specifies the configuration items that are to be attested.
// It is shared between the verifier and the provers.
Item attested_items[] = {
    { NV_MAGIC,            NV_OFFSET_MAGIC,            NV_LEN_MAGIC,            NV_TYPE_BYTE                },
    { NV_ID,               NV_OFFSET_ID,               NV_LEN_ID,               NV_TYPE_CHAR                },
    { NV_PROTOCOL,         NV_OFFSET_PROTOCOL,         NV_LEN_PROTOCOL,         NV_TYPE_CHAR                },
    { NV_ADDRESS,          NV_OFFSET_ADDRESS,          NV_LEN_ADDRESS,          NV_TYPE_CHAR                },
    { NV_PORT,             NV_OFFSET_PORT,             NV_LEN_PORT,             NV_TYPE_INT                 },
    { NV_KEY_DIST,         NV_OFFSET_KEY_DIST,         NV_LEN_KEY_DIST,         NV_TYPE_CHAR                },
    { NV_KEY_CHG_INTVL,    NV_OFFSET_KEY_CHG_INTVL,    NV_LEN_KEY_CHG_INTVL,    NV_TYPE_INT                 },
    { NV_ENCRYPT,          NV_OFFSET_ENCRYPT,          NV_LEN_ENCRYPT,          NV_TYPE_BOOL                },
    { NV_REPORT_INTVL,     NV_OFFSET_REPORT_INTVL,     NV_LEN_REPORT_INTVL,     NV_TYPE_INT                 },
    { NV_ATTEST,           NV_OFFSET_ATTEST,           NV_LEN_ATTEST,           NV_TYPE_BOOL                },
    { NV_SEEC,             NV_OFFSET_SEEC,             NV_LEN_SEEC,             NV_TYPE_BOOL                },
    { NV_KEY_ENCRYPTION,   NV_OFFSET_KEY_ENCRYPTION,   NV_LEN_KEY_ENCRYPTION,   NV_TYPE_BOOL                },
    { NV_SIGNING,          NV_OFFSET_SIGNING,          NV_LEN_SIGNING,          NV_TYPE_BOOL                },
    { NV_KEY_CHANGE,       NV_OFFSET_KEY_CHANGE,       NV_LEN_KEY_CHANGE,       NV_TYPE_BOOL                },
    { NV_PASSPORT_PERIOD,  NV_OFFSET_PASSPORT_PERIOD,  NV_LEN_PASSPORT_PERIOD,  NV_TYPE_INT                 },
    { NV_PAYLOAD_SIZE,     NV_OFFSET_PAYLOAD_SIZE,     NV_LEN_PAYLOAD_SIZE,     NV_TYPE_INT                 },
    { NV_PASS_THRU,        NV_OFFSET_PASS_THRU,        NV_LEN_PASS_THRU,        NV_TYPE_BOOL                },
    { NV_NUM_CYCLES,       NV_OFFSET_NUM_CYCLES,       NV_LEN_NUM_CYCLES,       NV_TYPE_INT                 },
    { NV_ITERATIONS,       NV_OFFSET_ITERATIONS,       NV_LEN_ITERATIONS,       NV_TYPE_INT                 },
    { NV_AUTHENTICATION,   NV_OFFSET_AUTHENTICATION,   NV_LEN_AUTHENTICATION,   NV_TYPE_BOOL                },

    { NV_ENC_KEY,          NV_OFFSET_ENC_KEY,          NV_LEN_ENC_KEY,          NV_TYPE_BYTE                },
    { NV_ATTEST_KEY,       NV_OFFSET_ATTEST_KEY,       NV_LEN_ATTEST_KEY,       NV_TYPE_BYTE                },
    { NV_AUTH_KEY,         NV_OFFSET_AUTH_KEY,         NV_LEN_AUTH_KEY,         NV_TYPE_BYTE                },

    { NV_PARAMS_SIZE,      NV_OFFSET_PARAMS_SIZE,      NV_LEN_PARAMS_SIZE,      NV_TYPE_INT                 },
    { NV_PARAMS,           NV_OFFSET_PARAMS,           NV_LEN_PARAMS,           NV_TYPE_BLOCK               },

    { NV_EURIPATH_SIZE,    NV_OFFSET_EURIPATH_SIZE,    NV_LEN_EURIPATH_SIZE,    NV_TYPE_INT                 },
    { NV_EURIPATH,         NV_OFFSET_EURIPATH,         NV_LEN_EURIPATH,         NV_TYPE_BLOCK               },

    { NV_SURIPATH_SIZE,    NV_OFFSET_SURIPATH_SIZE,    NV_LEN_SURIPATH_SIZE,    NV_TYPE_INT                 },
    { NV_SURIPATH,         NV_OFFSET_SURIPATH,         NV_LEN_SURIPATH,         NV_TYPE_BLOCK               },

    { NV_TIMEPATH_SIZE,    NV_OFFSET_TIMEPATH_SIZE,    NV_LEN_TIMEPATH_SIZE,    NV_TYPE_INT                 },
    { NV_TIMEPATH,         NV_OFFSET_TIMEPATH,         NV_LEN_TIMEPATH,         NV_TYPE_BLOCK               },

    { NV_SIGNKEY_SIZE,     NV_OFFSET_SIGNKEY_SIZE,     NV_LEN_SIGNKEY_SIZE,     NV_TYPE_INT                 },
    { NV_SIGNKEY,          NV_OFFSET_SIGNKEY,          NV_LEN_SIGNKEY,          NV_TYPE_BLOCK               },

    { NV_DOWNLOAD,         NV_OFFSET_DOWNLOAD,         NV_LEN_DOWNLOAD,         NV_TYPE_INT                 },
    { NV_DATA_TRANSPORT,   NV_OFFSET_DATA_TRANSPORT,   NV_LEN_DATA_TRANSPORT,   NV_TYPE_CHAR                },
};
