#ifndef __CS_ALERT_FASTLOG_H__
#define __CS_ALERT_FASTLOG_H__

#include <cs/cscommon.h>
#include <cs/PeriodicMultipleMetricsCollector.h>
#include "detect-nanomsg.h"
//#define URL_SIG "ipc:///tmp/signature-pipeline.ipc"
#define BUF_SIZE_SIG sizeof(SignatureData) * 1
static __thread NanomsgHandler nn_handler_sig;
static __thread char nn_init_sig = 0;

extern char fast_log_write_to_file;

static void FillAndSendSIGData(const Packet *p, const PacketAlert *pa) {
    //#COLLECTIVE_SENSE #CS_SIGNATURES #TIMEDELTA
    static METRIC_ID fastlog_metric_id = 0;

    if (fastlog_metric_id < 1)
        fastlog_metric_id = register_metric(MATCHED_SIGNATURES, (const char *)"suricata_collector");

    if( nn_init_sig == 0 ) {
        nn_init_sig = 1;
        NanomsgInit(&nn_handler_sig, nanomsg_url_sig, BUF_SIZE_SIG);
    }

    SignatureData* sd = (SignatureData*)NanomsgGetNextBufferElement(&nn_handler_sig, sizeof(SignatureData));
    sd->timestamp_usec = p->ts.tv_sec * 1000000L + p->ts.tv_usec;

    sd->sid = pa->s->id;

    if (pa->s->msg != NULL)
        strncpy(sd->msg, pa->s->msg, sizeof(sd->msg));
    else
        memset(sd->msg, 0, sizeof(sd->msg));

    if (pa->s->class_msg != NULL)
        strncpy(sd->class_msg, pa->s->class_msg, sizeof(sd->class_msg));
    else
        memset(sd->class_msg, 0, sizeof(sd->class_msg));

    sd->priority = pa->s->prio;

    //optionals
    sd->prot = IP_GET_IPPROTO(p);

    sd->src_ip[0] = 0;
    sd->src_ip[1] = 0;
    sd->dst_ip[0] = 0;
    sd->dst_ip[1] = 0;

    SetIp_NET32_TO_HOST64(GET_IPV4_SRC_ADDR_PTR(p), sd->src_ip);
    SetIp_NET32_TO_HOST64(GET_IPV4_DST_ADDR_PTR(p), sd->dst_ip);

    if (p->sp > 0)
        sd->src_port = p->sp;
    else
        sd->src_port = 0;

    if (p->dp > 0)
        sd->dst_port = p->dp;
    else
        sd->dst_port = 0;

    sd->flow_id = p->flow->flowInfo.flow_id;

    NanomsgSendBufferIfNeeded(&nn_handler_sig);
    update_metric(fastlog_metric_id, 1);
    //#COLLECTIVE_SENSE_END #CS_SIGNATURES_END
}
#endif
