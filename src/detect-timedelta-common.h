#pragma once

#include <stdint.h>


////////////////////////////////////////////////////////////////////////////////
//
// CONFIG
//
// You might want to make some of these configurable via rules file (like g_config_plugin_enabled)
//
////////////////////////////////////////////////////////////////////////////////

// logging
enum { TD_LOGLEVEL_ERROR, TD_LOGLEVEL_WARNING, TD_LOGLEVEL_INFO, TD_LOGLEVEL_DEBUG };

static const int g_config_logging_level           = TD_LOGLEVEL_ERROR;
//static const int g_config_logging_level           = TD_LOGLEVEL_DEBUG;
static const int g_config_logging_packets_enabled = 0;  // VERY CPU AND I/O INTENSIVE - use with caution
static const int g_config_logging_results_enabled = 0;
static const int g_config_logging_indent_width    = 2;  // how many spaces per indent

// plugin logic
int g_config_plugin_enabled; // read from plugin rules, enables/disables the plugin (useful for performance testing of Suricata's packet capture facility)

// Unified2 output
#define TD_OUTPUT_DIRNAME_MAX_LEN   1024

// enables extra debugging code which costs, so change it to #if 0 when you need performance
//#define TD_DEBUG

////////////////////////////////////////////////////////////////////////////////
//
// CONSTS/ENUMS/DEFINES - YOU SHOULDN'T NEED TO CHANGE THESE
//
////////////////////////////////////////////////////////////////////////////////

// FlowId
typedef uint64_t FlowId;       // \  Suricata's flow_id's are really just pointers to Flow structures, cast to an integer.

// convenience defines
#define MILLION  1000000        // so you don't have to count zeros when you see so many of them

// return codes/flags
#define TD_RET_ERR                      0
#define TD_RET_OK                       1
#define TD_RET_DUPLICATE_PACKET         3
#define TD_RET_IGNORED                  4
#define TD_RET_FLAG_OOO_ADDED           0x10000
#define TD_RET_FLAG_USED_T6_WITHOUT_T5  0x80000
#ifdef TD_DEBUG
 #define TD_RET_FLAG_OOO_PROCESSED      0x20000
 #define  TD_RET_CNT_OOO_PROCESSED      0x00100
 #define TD_RET_FLAG_FLOW_RESTARTED     0x40000
#else   // these flags are only used for debug/unit tests; compiler should optimise out our calculations invovling 0's
 #define TD_RET_FLAG_OOO_PROCESSED      0
 #define  TD_RET_CNT_OOO_PROCESSED      0
 #define TD_RET_FLAG_FLOW_RESTARTED     0
#endif
