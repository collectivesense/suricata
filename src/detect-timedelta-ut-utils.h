#pragma once

#include "suricata-common.h"
#include "detect-timedelta-utils.h"

////////////////////////////////////////////////////////////////////////////////
//
// UNIT TEST MICRO FRAMEWORK
//
////////////////////////////////////////////////////////////////////////////////

    #define TestIntEq( msg, expected, got ) ({      \
        int res = 0;                                \
        if( (expected) == (got) ) {                 \
            printf( "  %s: ok\n", (msg) ); res = 1; \
        } else {                                    \
            printf( "  %s: FAILED (expected = %lld, got = %lld) in %s:%d\n", (msg), ((long long)expected), ((long long)got), __FILE__, __LINE__ ); \
        }                                           \
        res;                                        \
        })

    #define TestIntNeq( msg, not_expected, got ) ({ \
        int res = 0;                                \
        if( (not_expected) != (got) ) {             \
            printf( "  %s: ok\n", (msg) ); res = 1; \
        } else {                                    \
            printf( "  %s: FAILED (not_expected = %lld) in %s:%d\n", (msg), ((long long)not_expected), __FILE__, __LINE__ ); \
        }                                           \
        res;                                        \
        })

    #define TestStrEq( msg, expected, got ) ({      \
        int res = 0;                                \
        if( !strncmp((expected), (got), 4096) ) {   \
            printf( "  %s: ok\n", (msg) ); res = 1; \
        } else {                                    \
            printf( "  %s: FAILED (expected = '%s', got = '%s') in %s:%d\n", (msg), (expected), (got), __FILE__, __LINE__ ); \
        }                                           \
        res;                                        \
        })





////////////////////////////////////////////////////////////////////////////////
//
// UNIT TEST HELPERS
//
////////////////////////////////////////////////////////////////////////////////

    #define TEST_IP_1 (uint32_t)( (192<<24) + (168<<16) + (  1<<8) +   1 )
    #define TEST_IP_2 (uint32_t)( (123<<24) + (123<<16) + (123<<8) + 123 )

    void UTH_FillPacket( Packet* packet, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint8_t tcp_flags, const char* payload );

