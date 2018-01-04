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

//Separates protocol and version bytes (major,minor)
//from the original packet version bytes.
static void LogTlsLogVer(uint8_t *protoEnum, uint16_t *verBytes, uint16_t version)
{
    switch (version) {
        case SSL_VERSION_2:
	    *protoEnum = 1;
	    *verBytes = 0x0200;
            break;
        case SSL_VERSION_3:
  	    *protoEnum = 1;
	    *verBytes = 0x0300;
            break;
        case TLS_VERSION_10:
  	    *protoEnum = 2;
	    *verBytes = 0x0100;
            break;
        case TLS_VERSION_11:
	    *protoEnum = 2;
	    *verBytes = 0x0101;
            break;
        case TLS_VERSION_12:
	    *protoEnum = 2;
	    *verBytes = 0x0102;
            break;
        //case TLS_VERSION_UNKNOWN: same as 'default'
        default:
	    *protoEnum = 0; // protocol is unknown
	    *verBytes = version; // set original version bytes?
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
    tls->proto = 0;
    tls->ver = 0;

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

    LogTlsLogVer(&tls->proto, &tls->ver, state->server_connp.version);

    tls->notBeforeSec = state->server_connp.cert0_not_before;
    tls->notAfterSec = state->server_connp.cert0_not_after;

    if (NULL != p->flow)
        tls->flow_id = p->flow->flowInfo.flow_id;
    else
        tls->flow_id = 0;

    NanomsgSendBufferIfNeeded(&nn_handler_tls);
    update_metric(tls_metric_id, 1);
}

#endif
