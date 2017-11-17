/* Copyright (C) 2007-2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Roliers Jean-Paul <popof.fpn@gmail.co>
 * \author Eric Leblond <eric@regit.org>
 * \author Victor Julien <victor@inliniac.net>
 * \author Paulo Pacheco <fooinha@gmail.com>
 *
 * Implements TLS logging portion of the engine. The TLS logger is
 * implemented as a packet logger, as the TLS parser is not transaction
 * aware.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "log-tlslog.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"
#include "util-time.h"
#include "log-cf-common.h"

#define DEFAULT_LOG_FILENAME "tls.log"

#define MODULE_NAME "LogTlsLog"

#define OUTPUT_BUFFER_SIZE 65535
#define CERT_ENC_BUFFER_SIZE 2048

#define LOG_TLS_DEFAULT            0
#define LOG_TLS_EXTENDED           1
#define LOG_TLS_CUSTOM             2
#define LOG_TLS_SESSION_RESUMPTION 4

#define LOG_TLS_CF_VERSION 'v'
#define LOG_TLS_CF_DATE_NOT_BEFORE 'd'
#define LOG_TLS_CF_DATE_NOT_AFTER 'D'
#define LOG_TLS_CF_SHA1 'f'
#define LOG_TLS_CF_SNI 'n'
#define LOG_TLS_CF_SUBJECT 's'
#define LOG_TLS_CF_ISSUER 'i'
#define LOG_TLS_CF_EXTENDED 'E'

//#COLLECTIVE_SENSE #DNS
#include <cs/cscommon.h>
#include <cs/PeriodicMultipleMetricsCollector.h>
#include "detect-nanomsg.h"
#include "detect-timedelta-utils.h"
//#define URL_DNS "ipc:///tmp/signature-pipeline.ipc"
#define BUF_SIZE_TLS sizeof(TLSData) * 10
static __thread NanomsgHandler nn_handler_tls;
static __thread char nn_init_tls = 0;
extern char tls_log_write_to_file;
//#COLLECTIVE_SENSE_END

typedef struct LogTlsFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
    LogCustomFormat *cf;
} LogTlsFileCtx;

typedef struct LogTlsLogThread_ {
    LogTlsFileCtx *tlslog_ctx;

    /** LogTlsFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t tls_cnt;

    MemBuffer *buffer;
} LogTlsLogThread;

static void LogTlsLogVersion(MemBuffer *buffer, uint16_t version)
{
    switch (version) {
        case TLS_VERSION_UNKNOWN:
            MemBufferWriteString(buffer, "VERSION='UNDETERMINED'");
            break;
        case SSL_VERSION_2:
            MemBufferWriteString(buffer, "VERSION='SSLv2'");
            break;
        case SSL_VERSION_3:
            MemBufferWriteString(buffer, "VERSION='SSLv3'");
            break;
        case TLS_VERSION_10:
            MemBufferWriteString(buffer, "VERSION='TLSv1'");
            break;
        case TLS_VERSION_11:
            MemBufferWriteString(buffer, "VERSION='TLS 1.1'");
            break;
        case TLS_VERSION_12:
            MemBufferWriteString(buffer, "VERSION='TLS 1.2'");
            break;
        default:
            MemBufferWriteString(buffer, "VERSION='0x%04x'", version);
            break;
    }
}

static void FillAndSendTLSData(char *srcip, char *dstip, Port sp, Port dp, const Packet *p, SSLState *state) {
    static METRIC_ID tls_metric_id = 0;

    if (tls_metric_id < 1)
        tls_metric_id = register_metric(TLS_RECORDS, (const char *)"suricata_collector");

    if (nn_init_tls == 0) {
        nn_init_tls = 1;
        NanomsgInit(&nn_handler_tls, nanomsg_url_tls, BUF_SIZE_TLS);
    }

    //tls
    TLSData* tls = (TLSData*) NanomsgGetNextBufferElement(&nn_handler_tls, sizeof(TLSData));

    tls->timestamp = GetTimestampInMicroSec(p->ts);
    tls->src_ip[0] = 0;
    tls->src_ip[1] = 0;
    tls->dst_ip[0] = 0;
    tls->dst_ip[1] = 0;

    SetIp_NET32_TO_HOST64(GET_IPV4_SRC_ADDR_PTR(p), tls->src_ip);
    SetIp_NET32_TO_HOST64(GET_IPV4_DST_ADDR_PTR(p), tls->dst_ip);

    if (sp > 0)
        tls->src_port = sp;
    else
        tls->src_port = 0;

    if (dp > 0)
        tls->dst_port = dp;
    else
        tls->dst_port = 0;

    memset(tls->issuerdn, 0, sizeof(tls->issuerdn));
    if (NULL != state->server_connp.cert0_issuerdn)
    {
        memcpy(tls->issuerdn, state->server_connp.cert0_issuerdn, MIN(sizeof(tls->issuerdn), strlen(state->server_connp.cert0_issuerdn)));
    }

    memset(tls->subject, 0, sizeof(tls->subject));
    if (NULL != state->server_connp.cert0_subject)
    {
        memcpy(tls->subject, state->server_connp.cert0_subject, MIN(sizeof(tls->subject), strlen(state->server_connp.cert0_subject)));
    }

    memset(tls->fingerPrint, 0, sizeof(tls->fingerPrint));
    if (state->server_connp.cert0_fingerprint != NULL) {
        memcpy(tls->fingerPrint, state->server_connp.cert0_fingerprint, MIN(sizeof(tls->fingerPrint), strlen(state->server_connp.cert0_fingerprint)));
    }

    memset(tls->sni, 0, sizeof(tls->sni));
    if (state->client_connp.sni != NULL) {
        memcpy(tls->sni, state->client_connp.sni, MIN(sizeof(tls->sni), strlen(state->client_connp.sni)));
    }

    MemBuffer temp;
    temp.buffer = (uint8_t*) tls->version;
    temp.size = sizeof(tls->version);
    temp.offset = 0;
    LogTlsLogVersion(&temp, state->server_connp.version);

    memset(tls->notBefore, 0, sizeof(tls->notBefore));
    if (state->server_connp.cert0_not_before != 0) {
        struct timeval tv;
        tv.tv_sec = state->server_connp.cert0_not_before;
        tv.tv_usec = 0;
        CreateUtcIsoTimeString(&tv, tls->notBefore, sizeof(tls->notBefore));
    }

    memset(tls->notAfter, 0, sizeof(tls->notAfter));
    if (state->server_connp.cert0_not_after != 0) {
        struct timeval tv;
        tv.tv_sec = state->server_connp.cert0_not_after;
        tv.tv_usec = 0;
        CreateUtcIsoTimeString(&tv, tls->notAfter, sizeof(tls->notAfter));
    }

    NanomsgSendBufferIfNeeded(&nn_handler_tls);
    update_metric(tls_metric_id, 1);
}

static void LogTlsLogDate(MemBuffer *buffer, const char *title, time_t *date)
{
    char timebuf[64] = {0};
    struct timeval tv;
    tv.tv_sec = *date;
    tv.tv_usec = 0;
    CreateUtcIsoTimeString(&tv, timebuf, sizeof(timebuf));
    MemBufferWriteString(buffer, "%s='%s'", title, timebuf);
}

static void LogTlsLogString(MemBuffer *buffer, const char *title, const char *value)
{
    MemBufferWriteString(buffer, "%s='%s'", title, value);
}

static void LogTlsLogExtended(LogTlsLogThread *aft, SSLState * state)
{
    if (state->server_connp.cert0_fingerprint != NULL) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogString(aft->buffer, "SHA1", state->server_connp.cert0_fingerprint);
    }
    if (state->client_connp.sni != NULL) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogString(aft->buffer, "SNI", state->client_connp.sni);
    }
    if (state->server_connp.cert0_serial != NULL) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogString(aft->buffer, "SERIAL", state->server_connp.cert0_serial);
    }

    LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
    LogTlsLogVersion(aft->buffer, state->server_connp.version);

    if (state->server_connp.cert0_not_before != 0) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogDate(aft->buffer, "NOTBEFORE", &state->server_connp.cert0_not_before);
    }
    if (state->server_connp.cert0_not_after != 0) {
        LOG_CF_WRITE_SPACE_SEPARATOR(aft->buffer);
        LogTlsLogDate(aft->buffer, "NOTAFTER", &state->server_connp.cert0_not_after);
    }
}

int TLSGetIPInformations(const Packet *p, char* srcip, size_t srcip_len,
                             Port* sp, char* dstip, size_t dstip_len,
                             Port* dp, int ipproto)
{
    if ((PKT_IS_TOSERVER(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), srcip, srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), dstip, dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->sp;
        *dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *) GET_IPV4_DST_ADDR_PTR(p), srcip, srcip_len);
                PrintInet(AF_INET, (const void *) GET_IPV4_SRC_ADDR_PTR(p), dstip, dstip_len);
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *) GET_IPV6_DST_ADDR(p), srcip, srcip_len);
                PrintInet(AF_INET6, (const void *) GET_IPV6_SRC_ADDR(p), dstip, dstip_len);
                break;
            default:
                return 0;
        }
        *sp = p->dp;
        *dp = p->sp;
    }
    return 1;
}

static TmEcode LogTlsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogTlsLogThread *aft = SCMalloc(sizeof(LogTlsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogTlsLogThread));

    if (initdata == NULL) {
        SCLogDebug( "Error getting context for TLSLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->tlslog_ctx = ((OutputCtx *) initdata)->data;

    *data = (void *) aft;
    return TM_ECODE_OK;
}

static TmEcode LogTlsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTlsLogThread *aft = (LogTlsLogThread *) data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogTlsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogTlsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogTlsFileCtx *tlslog_ctx = (LogTlsFileCtx *) output_ctx->data;
    LogFileFreeCtx(tlslog_ctx->file_ctx);
    LogCustomFormatFree(tlslog_ctx->cf);
    SCFree(tlslog_ctx);
    SCFree(output_ctx);
}

static void LogTlsLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogTlsLogThread *aft = (LogTlsLogThread *) data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("TLS logger logged %" PRIu32 " requests", aft->tls_cnt);
}

/** \brief Create a new tls log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *LogTlsLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "LogTlsLogInitCtx: Couldn't "
        "create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        goto filectx_error;
    }

    LogTlsFileCtx *tlslog_ctx = SCCalloc(1, sizeof(LogTlsFileCtx));
    if (unlikely(tlslog_ctx == NULL))
        goto filectx_error;
    tlslog_ctx->file_ctx = file_ctx;

    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    const char *custom = ConfNodeLookupChildValue(conf, "custom");
    const char *customformat = ConfNodeLookupChildValue(conf, "customformat");

    /* If custom logging format is selected, lets parse it */
    if (custom != NULL && customformat != NULL && ConfValIsTrue(custom)) {
        tlslog_ctx->cf = LogCustomFormatAlloc();
        if (!tlslog_ctx->cf) {
            goto tlslog_error;
        }

        tlslog_ctx->flags |= LOG_TLS_CUSTOM;
        /* Parsing */
        if ( ! LogCustomFormatParse(tlslog_ctx->cf, customformat)) {
            goto parser_error;
        }
    } else {
        if (extended == NULL) {
            tlslog_ctx->flags |= LOG_TLS_DEFAULT;
        } else {
            if (ConfValIsTrue(extended)) {
                tlslog_ctx->flags |= LOG_TLS_EXTENDED;
            }
        }
    }

    const char *session_resumption = ConfNodeLookupChildValue(conf, "session-resumption");
    if (session_resumption == NULL || ConfValIsTrue(session_resumption)) {
        tlslog_ctx->flags |= LOG_TLS_SESSION_RESUMPTION;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        goto tlslog_error;
    output_ctx->data = tlslog_ctx;
    output_ctx->DeInit = LogTlsLogDeInitCtx;

    SCLogDebug("TLS log output initialized");

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    return output_ctx;
parser_error:
    SCLogError(SC_ERR_INVALID_ARGUMENT,"Syntax error in custom tls log format string.");
tlslog_error:
    LogCustomFormatFree(tlslog_ctx->cf);
    SCFree(tlslog_ctx);
filectx_error:
    LogFileFreeCtx(file_ctx);
    return NULL;
}

/* Custom format logging */
static void LogTlsLogCustom(LogTlsLogThread *aft, SSLState *ssl_state, const struct timeval *ts,
                            char *srcip, Port sp, char *dstip, Port dp)
{
    LogTlsFileCtx *tlslog_ctx = aft->tlslog_ctx;
    uint32_t i;
    char buf[64];

    for (i = 0; i < tlslog_ctx->cf->cf_n; i++) {

        LogCustomFormatNode * node = tlslog_ctx->cf->cf_nodes[i];
        if (! node) /* Should never happen */
            continue;

        switch (node->type){
            case LOG_CF_LITERAL:
            /* LITERAL */
                MemBufferWriteString(aft->buffer, "%s", node->data);
                break;
            case LOG_CF_TIMESTAMP:
            /* TIMESTAMP */
                LogCustomFormatWriteTimestamp(aft->buffer, node->data, ts);
                break;
            case LOG_CF_TIMESTAMP_U:
            /* TIMESTAMP USECONDS */
                snprintf(buf, sizeof(buf), "%06u", (unsigned int) ts->tv_usec);
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)buf, MIN(strlen(buf),6));
                break;
            case LOG_CF_CLIENT_IP:
            /* CLIENT IP ADDRESS */
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)srcip,strlen(srcip));
                break;
            case LOG_CF_SERVER_IP:
            /* SERVER IP ADDRESS */
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)dstip,strlen(dstip));
                break;
            case LOG_CF_CLIENT_PORT:
            /* CLIENT PORT */
                MemBufferWriteString(aft->buffer, "%" PRIu16 "", sp);
                break;
            case LOG_CF_SERVER_PORT:
            /* SERVER PORT */
                MemBufferWriteString(aft->buffer, "%" PRIu16 "", dp);
                break;
            case LOG_TLS_CF_VERSION:
                LogTlsLogVersion(aft->buffer, ssl_state->server_connp.version);
                break;
            case LOG_TLS_CF_DATE_NOT_BEFORE:
                LogTlsLogDate(aft->buffer, "NOTBEFORE", &ssl_state->server_connp.cert0_not_before);
                break;
            case LOG_TLS_CF_DATE_NOT_AFTER:
                LogTlsLogDate(aft->buffer, "NOTAFTER", &ssl_state->server_connp.cert0_not_after);
                break;
            case LOG_TLS_CF_SHA1:
                if (ssl_state->server_connp.cert0_fingerprint != NULL) {
                    MemBufferWriteString(aft->buffer, "%s",
                                         ssl_state->server_connp.cert0_fingerprint);
                } else {
                    LOG_CF_WRITE_UNKNOWN_VALUE(aft->buffer);
                }
                break;
            case LOG_TLS_CF_SNI:
                if (ssl_state->client_connp.sni != NULL) {
                    MemBufferWriteString(aft->buffer, "%s",
                                         ssl_state->client_connp.sni);
                } else {
                    LOG_CF_WRITE_UNKNOWN_VALUE(aft->buffer);
                }
                break;
            case LOG_TLS_CF_SUBJECT:
                if (ssl_state->server_connp.cert0_subject != NULL) {
                    MemBufferWriteString(aft->buffer, "%s",
                                         ssl_state->server_connp.cert0_subject);
                } else {
                    LOG_CF_WRITE_UNKNOWN_VALUE(aft->buffer);
                }
                break;
            case LOG_TLS_CF_ISSUER:
                if (ssl_state->server_connp.cert0_issuerdn != NULL) {
                    MemBufferWriteString(aft->buffer, "%s",
                                         ssl_state->server_connp.cert0_issuerdn);
                } else {
                    LOG_CF_WRITE_UNKNOWN_VALUE(aft->buffer);
                }
                break;
            case LOG_TLS_CF_EXTENDED:
            /* Extended format  */
                LogTlsLogExtended(aft, ssl_state);
                break;
            default:
            /* NO MATCH */
                MemBufferWriteString(aft->buffer, LOG_CF_NONE);
                SCLogDebug("No matching parameter %%%c for custom tls log.", node->type);
                break;
        }
    }
    MemBufferWriteString(aft->buffer, "\n");
}


static int LogTlsLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                        Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogTlsLogThread *aft = (LogTlsLogThread *)thread_data;
    LogTlsFileCtx *hlog = aft->tlslog_ctx;
    char timebuf[64];
    int ipproto = (PKT_IS_IPV4(p)) ? AF_INET : AF_INET6;

    SSLState *ssl_state = (SSLState *)state;
    if (unlikely(ssl_state == NULL)) {
        return 0;
    }

    if (((hlog->flags & LOG_TLS_SESSION_RESUMPTION) == 0 ||
            (ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) == 0) &&
            (ssl_state->server_connp.cert0_issuerdn == NULL ||
            ssl_state->server_connp.cert0_subject == NULL)) {
        return 0;
    }

#define PRINT_BUF_LEN 46
    char srcip[PRINT_BUF_LEN], dstip[PRINT_BUF_LEN];
    Port sp, dp;
    if (!TLSGetIPInformations(p, srcip, PRINT_BUF_LEN, &sp, dstip,
                              PRINT_BUF_LEN, &dp, ipproto)) {
        return 0;
    }

    /* Custom format */
    if (hlog->flags & LOG_TLS_CUSTOM) {
        LogTlsLogCustom(aft, ssl_state, &p->ts, srcip, sp, dstip, dp);
    } else {

        MemBufferReset(aft->buffer);
        CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
        MemBufferWriteString(aft->buffer,
                             "%s %s:%d -> %s:%d  TLS:",
                             timebuf, srcip, sp, dstip, dp);

        if (ssl_state->server_connp.cert0_subject != NULL) {
            MemBufferWriteString(aft->buffer, " Subject='%s'",
                                 ssl_state->server_connp.cert0_subject);
        }
        if (ssl_state->server_connp.cert0_issuerdn != NULL) {
            MemBufferWriteString(aft->buffer, " Issuerdn='%s'",
                                 ssl_state->server_connp.cert0_issuerdn);
        }
        if (ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) {
            MemBufferWriteString(aft->buffer, " Session='resumed'");
        }

        if (hlog->flags & LOG_TLS_EXTENDED) {
            LogTlsLogExtended(aft, ssl_state);
            MemBufferWriteString(aft->buffer, "\n");
        } else {
            MemBufferWriteString(aft->buffer, "\n");
        }
    }

    aft->tls_cnt++;

    //#COLLECTIVE_SENSE
    FillAndSendTLSData(srcip, dstip, sp, dp, p, ssl_state);

    if (unlikely(TRUE == tls_log_write_to_file)) {
	hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
	MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);
    }
    //#COLLECTIVE_SENSE_END

    return 0;
}

void LogTlsLogRegister(void)
{
    OutputRegisterTxModuleWithProgress(LOGGER_TLS, MODULE_NAME, "tls-log",
        LogTlsLogInitCtx, ALPROTO_TLS, LogTlsLogger, TLS_HANDSHAKE_DONE,
        TLS_HANDSHAKE_DONE, LogTlsLogThreadInit, LogTlsLogThreadDeinit,
        LogTlsLogExitPrintStats);

    //#COLLECTIVE_SENSE
    if (TRUE == tls_log_write_to_file)
    {
        SCLogNotice("Output 'tls-log' will write to file. This may cause performance drawbacks.");
    }
    else
    {
        SCLogInfo("Output 'tls-log' will not write to file.");
    }
    //#COLLECTIVE_SENSE_END
}
