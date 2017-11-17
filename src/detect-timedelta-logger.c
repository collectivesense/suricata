////////////////////////////////////////////////////////////////////////////////
//
// LOGGING GUIDELINES - what level to use when:
//
//   debug -> things only interesting to a developer
//
//   info  -> normal events, like duplicate packet
//
//   wrn   -> things potentially suspicous, like:
//            abnormal events, like duplicate-but-different packet
//            dropping/timing out of packets
// 
//   error -> when something is obviously wrong
//
////////////////////////////////////////////////////////////////////////////////

#include "detect-timedelta-logger.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/time.h>

#include "util-time.h"
#include "util-debug.h"


// In the following code, to speed up the logging and to make the log much more legible, I used Suricata's lower-level functions.
// In other words, they will work unless Suricata changes their logging API (low probability, but hey, you never know).
// If it fails to compile one day, you can fall back to using higher-level functions by commenting-out below #define
// (not that they're an offical API either, so they too might change)
#define TD_LOGGING_USE_LOW_LEVEL


////////////////////////////////////////////////////////////////////////////////
//
// PUBLIC
//
////////////////////////////////////////////////////////////////////////////////

    #ifdef TD_LOGGING_USE_LOW_LEVEL
     static char* TDLogCommon_GetMessagePrefix            ( char* buf, const char* log_level, FlowId flow_id, int indent_level );
    #else
     static char* TDLogCommon_GetMessagePrefix_NoTimestamp( char* buf, const char* log_level, FlowId flow_id, int indent_level );
    #endif

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wformat-security"  // vsprintf() here has a dynamic format string, which GCC considers a security risk.  #pragmas are here to temporarily disable this warning

     #define TDLogCommon_GetMessage( buf_end, fmt )     \
     ({                                                 \
         va_list args;                                  \
         va_start( args, fmt );                         \
          vsprintf( buf_end, fmt, args );               \
         va_end( args );                                \
     })

     void TDLogDebug( FlowId flow_id, int indent_level, const char* fmt, ... )
     {
         if( g_config_logging_level < TD_LOGLEVEL_DEBUG )
             return;

         char buf[1024];

         #ifdef TD_LOGGING_USE_LOW_LEVEL
          char* buf_end = TDLogCommon_GetMessagePrefix            ( buf, "DBG", flow_id, indent_level );  TDLogCommon_GetMessage( buf_end, fmt );  SCLogWarning     ( SC_OK, buf ); //SCLogOutputBuffer( SC_OK, buf );
         #else
          char* buf_end = TDLogCommon_GetMessagePrefix_NoTimestamp( buf, "DBG", flow_id, indent_level );  TDLogCommon_GetMessage( buf_end, fmt );  SCLogWarning     ( SC_OK, buf );
         #endif
     }

     void TDLogInfo( FlowId flow_id, int indent_level, const char* fmt, ... )
     {
         if( g_config_logging_level < TD_LOGLEVEL_INFO )
             return;

         char buf[1024];

         #ifdef TD_LOGGING_USE_LOW_LEVEL
          char* buf_end = TDLogCommon_GetMessagePrefix            ( buf, "INF", flow_id, indent_level );  TDLogCommon_GetMessage( buf_end, fmt );  SCLogWarning     ( SC_OK, buf ); //SCLogOutputBuffer( SC_OK, buf );
         #else
          char* buf_end = TDLogCommon_GetMessagePrefix_NoTimestamp( buf, "INF", flow_id, indent_level );  TDLogCommon_GetMessage( buf_end, fmt );  SCLogWarning     ( SC_OK, buf );
         #endif
     }

     void TDLogWarning( FlowId flow_id, int indent_level, const char* fmt, ... )
     {
         if( g_config_logging_level < TD_LOGLEVEL_WARNING )
             return;

         char buf[1024];

         #ifdef TD_LOGGING_USE_LOW_LEVEL
          char* buf_end = TDLogCommon_GetMessagePrefix            ( buf, "WRN", flow_id, indent_level );  TDLogCommon_GetMessage( buf_end, fmt );  SCLogWarning     ( SC_OK, buf ); //SCLogOutputBuffer( SC_OK, buf );
         #else
          char* buf_end = TDLogCommon_GetMessagePrefix_NoTimestamp( buf, "WRN", flow_id, indent_level );  TDLogCommon_GetMessage( buf_end, fmt );  SCLogWarning     ( SC_OK, buf );
         #endif
     }

     void TDLogError( FlowId flow_id, int indent_level, const char* fmt, ... )
     {
         if( g_config_logging_level < TD_LOGLEVEL_ERROR )
             return;

         char buf[1024];

         #ifdef TD_LOGGING_USE_LOW_LEVEL
          char* buf_end = TDLogCommon_GetMessagePrefix            ( buf, "ERR", flow_id, indent_level );  TDLogCommon_GetMessage( buf_end, fmt );  SCLogWarning     ( SC_OK, buf ); //SCLogOutputBuffer( SC_OK, buf );
         #else
          char* buf_end = TDLogCommon_GetMessagePrefix_NoTimestamp( buf, "ERR", flow_id, indent_level );  TDLogCommon_GetMessage( buf_end, fmt );  SCLogWarning     ( SC_OK, buf );
         #endif
     }

    #pragma GCC diagnostic pop  // restore -Wformat-security



////////////////////////////////////////////////////////////////////////////////
//
// PRIVATE
//
////////////////////////////////////////////////////////////////////////////////

    static inline pid_t get_thread_id()
    {
        static __thread pid_t tid = 0;
        if( tid == 0 )
        {
            tid = syscall( SYS_gettid );
        }

        return tid;
    }


    #ifdef TD_LOGGING_USE_LOW_LEVEL

     static char* TDLogCommon_GetMessagePrefix( char* buf, const char* log_level, FlowId flow_id, int indent_level )
     {
         // to speed up the logging and make it more legible, I hacked at lower-level.  Let's hope Suricata won't change that much :)  Inspired by SCLogMessage()

         // get the time.  Copied from Suricata's SCLogMessage() - I hope they know what they're doing (if we're not using VDSO, this will probably hurt)
         struct timeval tval;
         gettimeofday( &tval, NULL );
         struct tm  local_tm;
         struct tm* tms = SCLocalTime( tval.tv_sec, &local_tm );

         // start with common prefix
         char* buf_end = buf + sprintf( buf, "%d/%d/%04d -- %02d:%02d:%02d TIMEDELTA %s [%d][%8lu] ", tms->tm_mday, tms->tm_mon + 1, tms->tm_year + 1900, tms->tm_hour, tms->tm_min, tms->tm_sec,
                                        log_level, get_thread_id(), flow_id );

         // append indentation
         int spaces = indent_level * g_config_logging_indent_width;
         memset( buf_end, ' ', spaces );
         buf_end += spaces;

         return buf_end;
     }

    #else

     static char* TDLogCommon_GetMessagePrefix_NoTimestamp( char* buf, const char* log_level, FlowId flow_id, int indent_level )
     {
         // this is a fallback version, unused at present, in case TDLogCommon_GetMessagePrefix() stopped working one day due to Suricata's code changing

         // start with common prefix
         char* buf_end = buf + sprintf( buf, "TIMEDELTA %s [%d][%8lu] ", log_level, get_thread_id(), flow_id );

         // append indentation
         int spaces = indent_level * g_config_logging_indent_width;
         memset( buf_end, ' ', spaces );
         buf_end += spaces;

         return buf_end;
     }

    #endif  // #ifdef TD_LOGGING_USE_LOW_LEVEL
