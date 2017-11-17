/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements dns logging portion of the engine.
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
#include "log-dnslog.h"
#include "app-layer-dns-common.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-time.h"

//#COLLECTIVE_SENSE #DNS
#include "detect-timedelta-utils.h"
#include <cs/cscommon.h>
#include <cs/PeriodicMultipleMetricsCollector.h>
#include "detect-nanomsg.h"
//#define URL_DNS "ipc:///tmp/signature-pipeline.ipc"
#define BUF_SIZE_DNS sizeof(DNSData) * 5
static __thread NanomsgHandler nn_handler_dns;
static __thread char nn_init_dns = 0;

extern char dns_log_write_to_file;
//#COLLECTIVE_SENSE_END

#define DEFAULT_LOG_FILENAME "dns.log"

#define MODULE_NAME "LogDnsLog"

#define OUTPUT_BUFFER_SIZE 65535

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

typedef struct LogDnsFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogDnsFileCtx;

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t dns_cnt;

    MemBuffer *buffer;
} LogDnsLogThread;

//#COLLECTIVE_SENSE #DNS
static void FillAndSendDNSInfo(const Packet *p, DNSTransaction *tx, DNSQueryEntry *qEntry, DNSAnswerEntry *aEntry) {
    //if (tx->tx_id > 65534 || tx->tx_id < 1) {
    //    printf("ERROR TX_INDEX value: %u it must be smaller than 65535 and bigger than 0!!! Invalid packet ?\n", tx->tx_id);
    //    return;
    //}

    static METRIC_ID dns_metric_id;
    static __thread uint64_t last_packet_ts;
    static __thread uint16_t r_num;
    //tx_id is a value from dns record, it has 2 bytes so there is 0-65535 possible values
    //array which contains timestamps of query packet for specific tx_id
    static __thread uint64_t tx_times[65536];
    //array which contains uri_or_ip of query packet for specific tx_id
    static __thread char tx_r_uri[65536][100];

    if (dns_metric_id < 1)
        dns_metric_id = register_metric(DNS_RECORDS, (const char*)"suricata_collector");

    if ( nn_init_dns == 0 ) {
        nn_init_dns = 1;
        NanomsgInit(&nn_handler_dns, nanomsg_url_dns, BUF_SIZE_DNS);
    }

    //DNS transaction
    DNSData* dns = (DNSData*)NanomsgGetNextBufferElement(&nn_handler_dns, sizeof(DNSData));
    dns->tx_id = tx->tx_id;
    dns->tx_type = NULL != qEntry ? 0 : 1;
    dns->timestamp = GetTimestampInMicroSec(p->ts);
    dns->delay = 0;

    if (dns->tx_type == 0)
        tx_times[dns->tx_id] = dns->timestamp;
    else
        if (tx_times[dns->tx_id] > 0)
            dns->delay = dns->timestamp - tx_times[dns->tx_id];
    //    else
    //        printf("WARNING query TS has not been set in tx_times[] tx_id: %d or has wrong value:%lu\n", dns->tx_id, tx_times[dns->tx_id]);

    if (dns->timestamp != last_packet_ts) { //assumption that each (next) packet will have different ts
        r_num = 0;
        last_packet_ts = dns->timestamp;
    }

    dns->r_num = r_num++; //special record number in packet
    dns->tx_rcode = NULL == aEntry && tx->rcode ? tx->rcode : 0;
    dns->tx_recursion_desired = NULL == aEntry && NULL == qEntry && tx->rcode == 0 && tx->recursion_desired ? 1 : 0;
    //IPs & ports
    dns->src_ip[0] = 0;
    dns->src_ip[1] = 0;
    dns->dst_ip[0] = 0;
    dns->dst_ip[1] = 0;

    SetIp_NET32_TO_HOST64(GET_IPV4_SRC_ADDR_PTR(p), dns->src_ip);
    SetIp_NET32_TO_HOST64(GET_IPV4_DST_ADDR_PTR(p), dns->dst_ip);
    dns->src_port = p->sp;
    dns->dst_port = p->dp;

    //Data
    dns->entry_ttl = NULL != aEntry ? aEntry->ttl : 0;
    dns->entry_type = NULL != aEntry ? aEntry->type : (NULL != qEntry ? qEntry->type : 0);

    memset (dns->uri_or_ip, 0, sizeof(dns->uri_or_ip));
    if (NULL != aEntry) {
        uint8_t *ptr = (uint8_t *)((uint8_t *)aEntry + sizeof(DNSAnswerEntry) + aEntry->fqdn_len);
        if (aEntry->type == DNS_RECORD_TYPE_A) {
            PrintInet(AF_INET, (const void *)ptr, dns->uri_or_ip, sizeof(dns->uri_or_ip));
        } else if (aEntry->type == DNS_RECORD_TYPE_AAAA) {
            PrintInet(AF_INET6, (const void *)ptr, dns->uri_or_ip, sizeof(dns->uri_or_ip));
        } else if (aEntry->data_len == 0) {
            //Mufasa or UI wanted it... do not ask me why...
            memcpy(dns->uri_or_ip, "<no data>", sizeof("<no data>"));
        } else {
            uint32_t temp = 0;
            PrintRawUriBuf(dns->uri_or_ip, &temp,
                    sizeof(dns->uri_or_ip), ptr, aEntry->data_len);
        }
    } else if (NULL != qEntry) {
        uint32_t temp = 0;
        PrintRawUriBuf((char *)dns->uri_or_ip, &temp, sizeof(dns->uri_or_ip),
                (uint8_t *)((uint8_t *)qEntry + sizeof(DNSQueryEntry)),
                qEntry->len);
    }
    //just in case...
    dns->uri_or_ip[sizeof(dns->uri_or_ip)-1] = '\0';

    if ( dns->tx_type == 0 ) {
        memcpy(tx_r_uri[dns->tx_id], dns->uri_or_ip, sizeof(dns->uri_or_ip));
        tx_r_uri[dns->tx_id][sizeof(dns->uri_or_ip)-1] = '\0';
    }

    memcpy(dns->r_uri_or_ip, tx_r_uri[dns->tx_id], sizeof(dns->r_uri_or_ip));
    dns->r_uri_or_ip[sizeof(dns->r_uri_or_ip)-1] = '\0';

    // printf("DNS RECORD:\n");
    // printf("dns->timestamp: %lu\n", dns->timestamp);
    // printf("dns->tx_id: %d\n", dns->tx_id);
    // printf("delay: %d\n", dns->delay);
    // printf("dns->tx_type: %d\n", dns->tx_type);
    // printf("dns->r_num: %d\n", dns->r_num);
    // printf("dns->tx_rcode: %d\n", dns->tx_rcode);
    // printf("dns->tx_recursion_desired: %d\n", dns->tx_recursion_desired);
    // printf("dns->entry_ttl: %d\n", dns->entry_ttl);
    // printf("dns->entry_type: %d\n", dns->entry_type);
    // //printf("dstip: %s\n", dstip);
    // printf("dns->dst_ip: %d\n", dns->dst_ip[0]);
    // //printf("srcip: %s\n", srcip);
    // printf("dns->src_ip: %d\n", dns->src_ip[0]);
    // //printf("sp: %d\n", sp);
    // printf("dns->src_port: %d\n", dns->src_port);
    // //printf("dp: %d\n", dp);
    // printf("dns->dst_port: %d\n", dns->dst_port);
    // printf("dns->uri_or_ip: %s\n", dns->uri_or_ip);
    // printf("dns->ruri_or_ip: %s\n", dns->r_uri_or_ip);

    NanomsgSendBufferIfNeeded(&nn_handler_dns);
    update_metric(dns_metric_id, 1);
}
//#COLLECTIVE_SENSE_END #DNS

static void LogQuery(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx, DNSQueryEntry *entry, const Packet *p)
{
    //#COLLECTIVE_SENSE #DNS
    FillAndSendDNSInfo(p, tx, entry, NULL);

    if (likely(FALSE == dns_log_write_to_file))
    {
        return;
    }
    //#COLLECTIVE_SENSE_END #DNS

    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS request and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);

    /* time & tx */
    MemBufferWriteString(aft->buffer,
            "%s [**] Query TX %04x [**] ", timebuf, tx->tx_id);

    /* query */
    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
            (uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)),
            entry->len);

    char record[16] = "";
    DNSCreateTypeString(entry->type, record, sizeof(record));
    MemBufferWriteString(aft->buffer,
            " [**] %s [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
            record, srcip, sp, dstip, dp);

    hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);
}

static void LogAnswer(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx, DNSAnswerEntry *entry, const Packet *p)
{
    //#COLLECTIVE_SENSE #DNS
    FillAndSendDNSInfo(p, tx, NULL, entry);

    if (likely(FALSE == dns_log_write_to_file))
    {
        return;
    }
    //#COLLECTIVE_SENSE_END #DNS

    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS response and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);
    /* time & tx*/
    MemBufferWriteString(aft->buffer,
            "%s [**] Response TX %04x [**] ", timebuf, tx->tx_id);

    if (entry == NULL) {
        if (tx->rcode) {
            char rcode[16] = "";
            DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
            MemBufferWriteString(aft->buffer, "%s", rcode);
        } else if (tx->recursion_desired) {
            MemBufferWriteString(aft->buffer, "Recursion Desired");
        }
    } else {
        /* query */
        if (entry->fqdn_len > 0) {
            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                    (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)),
                    entry->fqdn_len);
        } else {
            MemBufferWriteString(aft->buffer, "<no data>");
        }

        char record[16] = "";
        DNSCreateTypeString(entry->type, record, sizeof(record));
        MemBufferWriteString(aft->buffer,
                " [**] %s [**] TTL %u [**] ", record, entry->ttl);

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry) + entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A && entry->data_len == 4) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            MemBufferWriteString(aft->buffer, "%s", a);
        } else if (entry->type == DNS_RECORD_TYPE_AAAA && entry->data_len == 16) {
            char a[46];
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            MemBufferWriteString(aft->buffer, "%s", a);
        } else if (entry->data_len == 0) {
            MemBufferWriteString(aft->buffer, "<no data>");
        } else {
            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                    aft->buffer->size, ptr, entry->data_len);
        }
    }

    /* ip/tcp header info */
    MemBufferWriteString(aft->buffer,
            " [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
            srcip, sp, dstip, dp);

    hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);
}

static int LogDnsLogger(ThreadVars *tv, void *data, const Packet *p,
    Flow *f, void *state, void *tx, uint64_t tx_id, uint8_t direction)
{
#ifdef HAVE_RUST
    SCLogNotice("LogDnsLogger not implemented for Rust DNS.");
    return 0;
#endif
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    DNSTransaction *dns_tx = (DNSTransaction *)tx;
    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    int ipproto = 0;
    if (PKT_IS_IPV4(p))
        ipproto = AF_INET;
    else if (PKT_IS_IPV6(p))
        ipproto = AF_INET6;

    char srcip[46], dstip[46];
    Port sp, dp;
    if ((PKT_IS_TOCLIENT(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->dp;
        dp = p->sp;
    }

    if (direction == STREAM_TOSERVER) {
        DNSQueryEntry *query = NULL;
        TAILQ_FOREACH(query, &dns_tx->query_list, next) {
            LogQuery(aft, timebuf, dstip, srcip, dp, sp, dns_tx, query, p);
        }
    } else if (direction == STREAM_TOCLIENT) {
        if (dns_tx->rcode)
            LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, NULL, p);
        if (dns_tx->recursion_desired)
            LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, NULL, p);

        DNSAnswerEntry *entry = NULL;
        TAILQ_FOREACH(entry, &dns_tx->answer_list, next) {
            LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, entry, p);
        }

        entry = NULL;
        TAILQ_FOREACH(entry, &dns_tx->authority_list, next) {
            LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, entry, p);
        }
    }

    aft->dns_cnt++;
end:
    return 0;
}

static int LogDnsRequestLogger(ThreadVars *tv, void *data, const Packet *p,
    Flow *f, void *state, void *tx, uint64_t tx_id)
{
    return LogDnsLogger(tv, data, p, f, state, tx, tx_id, STREAM_TOSERVER);
}

static int LogDnsResponseLogger(ThreadVars *tv, void *data, const Packet *p,
    Flow *f, void *state, void *tx, uint64_t tx_id)
{
    return LogDnsLogger(tv, data, p, f, state, tx, tx_id, STREAM_TOCLIENT);
}

static TmEcode LogDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDnsLogThread *aft = SCMalloc(sizeof(LogDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogDnsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for LogDNSLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->dnslog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogDnsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogDnsLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("DNS logger logged %" PRIu32 " transactions", aft->dns_cnt);
}

static void LogDnsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    LogFileFreeCtx(dnslog_ctx->file_ctx);
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *LogDnsLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_DNS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(dnslog_ctx);
        return NULL;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtx;

    SCLogDebug("DNS log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    return output_ctx;
}

void LogDnsLogRegister (void)
{
    /* Request logger. */
    OutputRegisterTxModuleWithProgress(LOGGER_DNS, MODULE_NAME, "dns-log",
        LogDnsLogInitCtx, ALPROTO_DNS, LogDnsRequestLogger, 0, 1,
        LogDnsLogThreadInit, LogDnsLogThreadDeinit, LogDnsLogExitPrintStats);

    /* Response logger. */
    OutputRegisterTxModuleWithProgress(LOGGER_DNS, MODULE_NAME, "dns-log",
        LogDnsLogInitCtx, ALPROTO_DNS, LogDnsResponseLogger, 1, 1,
        LogDnsLogThreadInit, LogDnsLogThreadDeinit, LogDnsLogExitPrintStats);

    /* enable the logger for the app layer */
    SCLogDebug("registered %s", MODULE_NAME);

    //#COLLECTIVE_SENSE #DNS
    if (TRUE == dns_log_write_to_file)
    {
        SCLogNotice("Output 'dns-log' will write to file. This may cause performance drawbacks.");
    }
    else
    {
        SCLogInfo("Output 'dns-log' will not write to file.");
    }
    //#COLLECTIVE_SENSE_END #DNS
}
