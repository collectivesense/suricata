#ifndef __CS_LOG_TLSLOG_H__
#define __CS_LOG_TLSLOG_H__

//#COLLECTIVE_SENSE #DNS
#include <cs/cscommon.h>
#include <cs/PeriodicMultipleMetricsCollector.h>
#include "detect-nanomsg.h"
#include "detect-timedelta-utils.h"
#define BUF_SIZE_TLS sizeof(TLSData) * 10
static __thread NanomsgHandler nn_handler_tls;
static __thread char nn_init_tls = 0;
extern char tls_log_write_to_file;
//#COLLECTIVE_SENSE_END

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
    if (NULL != state->server_connp.cert0_issuerdn) {
        memcpy(tls->issuerdn, state->server_connp.cert0_issuerdn, MIN(sizeof(tls->issuerdn), strlen(state->server_connp.cert0_issuerdn)));
    }

    memset(tls->subject, 0, sizeof(tls->subject));
    if (NULL != state->server_connp.cert0_subject) {
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

    tls->flow_id = p->flow->flowInfo.flow_id;

    NanomsgSendBufferIfNeeded(&nn_handler_tls);
    update_metric(tls_metric_id, 1);
}

#endif
