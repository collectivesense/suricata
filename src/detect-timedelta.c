// Suricata
#include "suricata-common.h"
#include "util-unittest.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-hash.h"

// our plugin
#include <cs/cscommon.h>
#include "detect-timedelta.h"
#include "detect-timedelta-flow.h"          // structs and related functions (you can think of them as classes and methods if you're familiar with OOP)
#include "detect-timedelta-processing.h"    // packet processing, the heart of the plugin
#include "detect-capture.h"

// unit tests
#include "detect-timedelta-processing-ut.h"
#include "detect-timedelta-ut.h"

////////////////////////////////////////////////////////////////////////////////
//
// PLUGIN PROCESSING
//
////////////////////////////////////////////////////////////////////////////////

// THIS FUNCTION IS CALLED EVERY TIME A NEW PACKET IS RECEIVED.  IT IS THE ENTRYPOINT TO THIS PLUGIN

int DetectTimeDeltaMatch( ThreadVars* thread_vars, DetectEngineThreadCtx* det_ctx, Packet* packet, const Signature* sig, const SigMatchCtx* sig_match )
{
    // bypass processing - useful for performance testing of the actual capture library (pfring,afpacket,pcap,etc)
    if ( !g_config_plugin_enabled ) {
        return 0;
    }

    // we have to call this every time, because I haven't found a better way, and per-thread init doesn't exist!!!  More precisely, it probably does,
    // but it's not well documented (https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Thread_Modules is all that I found on the subject.
    // Sample helloworld program I used as a starting point does not mention thread initialisation at all).  It turns out that what we've been relying on
    // (DetectTimeDeltaSetup()) is called per rule, because its purpose is to initialise rules rather than threads.  So what we have here sucks, but the
    // proper way of doing this hasn't been documented).
    //InitFlowInfoHTifNecessary();

    // check packet, flow, TCP header and flags
    if ( packet == NULL ||  packet->recursion_level > 0 ) {
        TDLogInfo( 0, 0, "Packet is NULL or recursion_level > 0! Ignored!" );
        return TD_RET_IGNORED;
    }

    // log the packet - VERY CPU intenstive, use with caution
    if ( g_config_logging_packets_enabled ) {
        LogPacket( packet );
    }

    //REJECT packets whith unknown PROTOCOL like ARP etc...
    //sp and dp conditions are just in case...
    if (packet->proto == 0 && packet->sp == 0 && packet->dp == 0)
        return 0;

    SetPacketFlowIdAndPacketId(packet);
    //PacketTSValidationAndFix(packet);

    //RTCP CAPTURE HANDLER
    if ( is_rtcp_packet(packet->payload, packet->payload_len)
        && packet->sp > 1024 //aditional most common ports (because rfc mask algo is not as precisely as we expect)
        && packet->dp > 1024 ) {
        RTCPCapture(packet);
    }

    //PACKET HEADER CAPTURE HANDLER
    //Let's risk capturing packet without a flow
    PacketHeaderCapture(packet);

    // the core plugin functionality
    if(packet->proto == 6)
        PacketHandler( packet, (FlowId) packet->flow, 0, NULL );

    // return no match (I think Suricata would log it if we returned 1, and there's no point in doing that)
    return 0;   //TODO see if 1 vs 0 affects performance, maybe 1 ceases inspection of other rules
}

////////////////////////////////////////////////////////////////////////////////
//
// PLUGIN LIFECYCLE
//
////////////////////////////////////////////////////////////////////////////////

static int g_setup_ref_counter = 0; //TODO might need it to be thread-local

// --[ Suricata entrypoints ]---------------------------------------------------

void DetectTimeDeltaRegister(void)
{
    // THIS FUNCTION IS CALLED ONLY ONCE (no matter how many threads or rules you have)

    TDLogDebug( 0, 0, "DetectTimeDeltaRegister()" );

    SanityCheck();

    RegisterSigmatchTable();

    CompileRegex();

}

void DetectTimeDeltaFree(void *ptr)
{
    // THIS FUNCTION IS CALLED MANY TIMES, ie: with every rule

    TDLogDebug( 0, 0, "DetectTimeDeltaFree()" );
    g_setup_ref_counter--;

    // ref-counted resource freeing
    if( g_setup_ref_counter == 0 )
    {
        TDLogInfo( 0, 1, "Reference count at 0, freeing resources" );
        FreeConfig( ptr );
    }
    else
    {
        TDLogInfo( 0, 1, "Reference count at %d, not freeing resources", g_setup_ref_counter );
    }
}

static int DetectTimeDeltaSetup( DetectEngineCtx* de_ctx, Signature* s, const char* config_string)
{
    // THIS FUNCTION IS CALLED: once per every rule, but not per thread (so if you have 15 threads and 3 rules, it will be called 3 times)

    TDLogDebug( 0, 0, "DetectTimeDeltaSetup()" );
    g_setup_ref_counter++;

    DetectTimeDeltaData* config = NULL;
    SigMatch*            sm     = NULL;

    config = ReadConfig( config_string );
    if( config == NULL )
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_TIMEDELTA;
    sm->ctx = (void *)config;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    g_config_plugin_enabled = config->plugin_enabled;

    return 0;

error:
    if (config != NULL) FreeConfig(config);
    if (sm     != NULL) SCFree(sm);
    return -1;
}

// --[ private functions ]------------------------------------------------------

void SanityCheck()
{
    if( sizeof(Flow*) != sizeof(FlowId) ) {
        TDLogError( 0, 0, "Portability issue.  See FlowId typedef for more information." );
        exit( EXIT_FAILURE );
    }

    FlowInfo fi;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtautological-compare"
    if( &fi != (FlowInfo*) &(fi.flow_id) ) {
        TDLogError( 0, 0, "flow_id must be the 1st member of FlowInfo - hashtable semantics in this plugin rely on this property." );
        exit( EXIT_FAILURE );
    }
#pragma GCC diagnostic pop

}

void RegisterSigmatchTable()
{
    sigmatch_table[DETECT_TIMEDELTA].name = "timedelta";
    sigmatch_table[DETECT_TIMEDELTA].desc = "<todo>";
    sigmatch_table[DETECT_TIMEDELTA].url = "<todo>";
    sigmatch_table[DETECT_TIMEDELTA].Match = DetectTimeDeltaMatch;
    sigmatch_table[DETECT_TIMEDELTA].Setup = DetectTimeDeltaSetup;
    sigmatch_table[DETECT_TIMEDELTA].Free  = DetectTimeDeltaFree;
    sigmatch_table[DETECT_TIMEDELTA].RegisterTests = DetectTimeDeltaRegisterTests;
}

void CompileRegex()
{
    parse_regex_study = NULL;
    parse_regex       = NULL;

    const char* eb;
    int         eo;
    int         opts = 0;

    parse_regex = pcre_compile( PARSE_REGEX, opts, &eb, &eo, NULL );
    if( parse_regex == NULL ) {
        TDLogError( 0, 0, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb );
        goto error;
    }

    parse_regex_study = pcre_study( parse_regex, 0, &eb );
    if( eb != NULL ) {
        TDLogError( 0, 0, "pcre study failed: %s", eb );
        goto error;
    }

    return;

error:
    if( parse_regex       != NULL ) SCFree(parse_regex);
    if( parse_regex_study != NULL ) SCFree(parse_regex_study);
}

DetectTimeDeltaData* ReadConfig( const char* config_string )
{
    TDLogInfo( 0, 0, "Reading configuration" );

    // init vars
    const int MAX_SUBSTRINGS = 30;
    DetectTimeDeltaData *config = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    // run regex
    ret = pcre_exec(parse_regex, parse_regex_study, config_string, strlen(config_string), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        TDLogError( 0, 0, "parse error, ret %" PRId32 "", ret );
        goto error;
    }
    const char *str_ptr;

    // get 1st argument from regex (unified2 output directory)
    res = pcre_get_substring((char *) config_string, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        TDLogError( 0, 0, "pcre_get_substring failed" );
        goto error;
    }
    arg1 = (char *) str_ptr;
    TDLogDebug( 0, 0, "Arg1 (output directory) \"%s\"", arg1 );

    // get 2nd argument from regex (plugin enable/disable)
    if (ret >= 3) {
        res = pcre_get_substring((char *) config_string, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            TDLogError( 0, 0, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        TDLogDebug( 0, 0, "Arg2 \"%s\"", arg2 );
    }

    // set configuration: malloc
    config = SCMalloc( sizeof (DetectTimeDeltaData) );
    if( unlikely(config == NULL) )
        goto error;

    // set configuration: set output directory
    size_t len = strnlen( arg1, TD_OUTPUT_DIRNAME_MAX_LEN );
    if( len >= TD_OUTPUT_DIRNAME_MAX_LEN )
    {
        TDLogError( 0, 0, "Output directory in configuration is too long!  Maximum allowed length = %d", TD_OUTPUT_DIRNAME_MAX_LEN );
        goto error;
    }
    else if( len > 0 )
    {
        strncpy( config->unified2_output_dir, arg1, TD_OUTPUT_DIRNAME_MAX_LEN );
    }
    else
    {
        strcpy( config->unified2_output_dir, "./" );
    }

    // set configuration: set enable/disable plugin
    config->plugin_enabled = (uint8_t)atoi(arg2);

    SCFree(arg1);
    SCFree(arg2);
    return config;

error:
    if (config)  SCFree(config);
    if (arg1)    SCFree(arg1);
    if (arg2)    SCFree(arg2);
    return NULL;
}

void FreeConfig( void* ptr )
{
    DetectTimeDeltaData* config = (DetectTimeDeltaData*) ptr;
    SCFree( config );
}

////////////////////////////////////////////////////////////////////////////////
//
// UNIT TESTS
//
////////////////////////////////////////////////////////////////////////////////

void DetectTimeDeltaRegisterTests()
{
    #ifdef UNITTESTS
     UtRegisterTest( "DetectTimeDeltaTestCore",        TestCore, 1 );
     UtRegisterTest( "DetectTimeDeltaSignatureTest01", DetectTimeDeltaSignatureTest01, 1 );

     UtRegisterTest( "DetectTimeDeltaTestProcessing", TestProcessing, 1 );
     UtRegisterTest( "DetectTimeDeltaTestUnified2",   TestUnified2,   1 );
    #endif
}
