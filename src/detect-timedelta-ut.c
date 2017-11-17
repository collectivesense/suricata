#include "suricata-common.h"
#include "util-unittest.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-hash.h"

#include "detect-timedelta.h"
#include "detect-timedelta-ut.h"
#include "detect-timedelta-ut-utils.h"

static int TestCore_Config_OutputDir1()
{
    DetectTimeDeltaData* config = NULL;
    int res = 1;

    config = ReadConfig( ".,10" );

    res &= TestIntNeq( "Parsing config successful",         NULL, config                      );
    res &= TestStrEq ( "Output dir should be set to '.'",   ".",  config->unified2_output_dir );

    FreeConfig( config );

    return res;
}

static int TestCore_Config_OutputDir2()
{
    DetectTimeDeltaData* config = NULL;
    int res = 1;

    config = ReadConfig( ",10" );

    res &= TestIntNeq( "Parsing config successful",          NULL, config                      );
    res &= TestStrEq ( "Output dir should be set to './'",   "./", config->unified2_output_dir );

    FreeConfig( config );

    return res;
}

static int TestCore_Config_OutputDir3()
{
    DetectTimeDeltaData* config = NULL;
    int res = 1;

    config = ReadConfig( "/var/log/suricata/output,10" );

    res &= TestIntNeq( "Parsing config successful",        NULL, config                      );
    res &= TestStrEq ( "Output dir should be set to '/var/log/suricata/output'",   "/var/log/suricata/output",   config->unified2_output_dir );

    FreeConfig( config );

    return res;
}

static int TestCore_Config_OutputDir4()
{
    DetectTimeDeltaData* config = NULL;
    int res = 1;

    config = ReadConfig( "   /var/log/suricata/output   ,10" );

    res &= TestIntNeq( "Parsing config successful",        NULL, config                      );
    res &= TestStrEq ( "Output dir should be set to '/var/log/suricata/output'",   "/var/log/suricata/output",   config->unified2_output_dir );

    FreeConfig( config );

    return res;
}

int TestCore()
{
    int res = 1;
    printf( "\n" ); // calling code doesn't line-feed

    printf( "Running TestCore_Config_OutputDir1()\n" ); res &= TestCore_Config_OutputDir1();
    printf( "Running TestCore_Config_OutputDir2()\n" ); res &= TestCore_Config_OutputDir2();
    printf( "Running TestCore_Config_OutputDir3()\n" ); res &= TestCore_Config_OutputDir3();
    printf( "Running TestCore_Config_OutputDir4()\n" ); res &= TestCore_Config_OutputDir4();

    return res;
}





int DetectTimeDeltaSignatureTest01()
{
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (timedelta:1,10; sid:1; rev:1;)");
    if (sig == NULL) {
        printf("parsing signature failed: ");
        goto end;
    }

    /* if we get here, all conditions pass */
    res = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return res;
}

