/**
 * \file
 *
 * \author Yourname <youremail@yourdomain>
 */
#pragma once

#include "detect-timedelta-common.h"

////////////////////////////////////////////////////////////////////////////////
//
// SURICATA API
//
////////////////////////////////////////////////////////////////////////////////

    void DetectTimeDeltaRegister(void);





////////////////////////////////////////////////////////////////////////////////
//
// INTERNAL (BUT UNIT TESTS CALL THESE)
//
////////////////////////////////////////////////////////////////////////////////

    typedef struct DetectTimeDeltaData_
    {
        char    unified2_output_dir[TD_OUTPUT_DIRNAME_MAX_LEN]; // 1st value: log directory where Unified2 files will be created
        uint8_t plugin_enabled;                                 // 2nd value: enables/disables all processing (useful for testing Suricata performance)
    }
    DetectTimeDeltaData;

    DetectTimeDeltaData* ReadConfig( const char* config_string );
    void                 FreeConfig( void* );

