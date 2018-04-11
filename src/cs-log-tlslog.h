#ifndef __CS_LOG_TLSLOG_H__
#define __CS_LOG_TLSLOG_H__

//#COLLECTIVE_SENSE #DNS
#include <cs/cscommon.h>
#include "detect-nanomsg.h"
#include "detect-timedelta-utils.h"
#define BUF_SIZE_TLS sizeof(TLSData) * 10
static __thread NanomsgHandler nn_handler_tls;
static __thread char nn_init_tls = 0;
extern char tls_log_write_to_file;
//#COLLECTIVE_SENSE_END

//Converts original version bytes from packet
//to single byte protocol and version enum
static uint8_t DecodeTlsVersion(uint16_t version)
{
    switch (version) {
        case SSL_VERSION_2:
	    return CS_TLS_VER_SSL_2;
        case SSL_VERSION_3:
	    return CS_TLS_VER_SSL_3;
        case TLS_VERSION_10:
	    return CS_TLS_VER_10;
        case TLS_VERSION_11:
	    return CS_TLS_VER_11;
        case TLS_VERSION_12:
	    return CS_TLS_VER_12;
        //case TLS_VERSION_UNKNOWN: same as 'default'
        default:
	    return CS_TLS_VER_UNKNOWN;
    }
}

static void FillAndSendTLSData(char *srcip, char *dstip, Port sp, Port dp, const Packet *p, SSLState *state) {
    if (nn_init_tls == 0) {
        nn_init_tls = 1;
        NanomsgInit(&nn_handler_tls, nanomsg_url_tls, sizeof(TLSData), TLS_RECORDS);
    }

    //tls
    TLSData* tls = (TLSData*) NanomsgGetNextBufferElement(&nn_handler_tls);

    tls->timestamp = GetTimestampInMicroSec(p->ts);
    tls->src_ip[0] = 0;
    tls->src_ip[1] = 0;
    tls->dst_ip[0] = 0;
    tls->dst_ip[1] = 0;
    tls->version = CS_TLS_VER_UNKNOWN;

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

    tls->version = DecodeTlsVersion(state->server_connp.version);

    tls->notBeforeSec = state->server_connp.cert0_not_before;
    tls->notAfterSec = state->server_connp.cert0_not_after;

    if (NULL != p->flow)
        tls->flow_id = p->flow->flowInfo.flow_id;
    else
        tls->flow_id = 0;

    NanomsgSendBufferIfNeeded(&nn_handler_tls);
}

#endif
