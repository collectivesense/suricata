#pragma once

#include "suricata-common.h"

#include "detect-timedelta-common.h"

////////////////////////////////////////////////////////////////////////////////
//
// TIME FUNCTIONS
//
////////////////////////////////////////////////////////////////////////////////

    typedef uint64_t TimeInMicroSec;

    inline TimeInMicroSec GetTimestampDiff( struct timeval ts1, struct timeval ts2 )
    {
        return MILLION*( ts1.tv_sec  - ts2.tv_sec  )
                  +    ( ts1.tv_usec - ts2.tv_usec );
    }

    inline TimeInMicroSec GetTimestampInMicroSec( struct timeval ts )
    {
        //printf("####### GetTimestampInMicroSec: sec: %u, usec: %u\n", ts.tv_sec, ts.tv_usec);
        if (ts.tv_usec >= MILLION)
            return MILLION*ts.tv_sec + ts.tv_usec / 1000;
        else
            return MILLION*ts.tv_sec + ts.tv_usec;
    }

    inline TimeInMicroSec GetTimestampInNanoSec( struct timeval ts )
    {
        //printf("####### GetTimestampInNanoSec: sec: %u, nsec: %u\n", ts.tv_sec, ts.tv_usec);
        if (ts.tv_usec < MILLION)
            return MILLION*1000*ts.tv_sec + ts.tv_usec * 1000;
        else
            return MILLION*1000*ts.tv_sec + ts.tv_usec;
    }

    extern __thread TimeInMicroSec g_current_time;    // in order to avoid expensive time() syscall, we keep track of latest time by extracting it from packets and storing it here for future use

    void   UpdateCurrentTime( TimeInMicroSec now, FlowId flow_id );

    inline TimeInMicroSec GetCurrentTime()
    {
        return g_current_time;
    }


////////////////////////////////////////////////////////////////////////////////
//
// PACKET LOGGING
//
////////////////////////////////////////////////////////////////////////////////

    void LogPacket( Packet* packet );
