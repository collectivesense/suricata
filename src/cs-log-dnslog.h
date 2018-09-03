#ifndef __CS_LOG_DNSLOG_H__
#define __CS_LOG_DNSLOG_H__

#include "detect-timedelta-utils.h"
#include <cs/cscommon.h>
#include "detect-nanomsg.h"

#define BUF_SIZE_DNS sizeof(DNSData) * 5
static __thread NanomsgHandler nn_handler_dns;
static __thread char nn_init_dns = 0;

extern char dns_log_write_to_file;

//#COLLECTIVE_SENSE #DNS
static void FillAndSendDNSInfo(const Packet *p, DNSTransaction *tx, DNSQueryEntry *qEntry, DNSAnswerEntry *aEntry) {
    //if (tx->tx_id > 65534 || tx->tx_id < 1) {
    //    printf("ERROR TX_INDEX value: %u it must be smaller than 65535 and bigger than 0!!! Invalid packet ?\n", tx->tx_id);
    //    return;
    //}

    static __thread uint64_t last_packet_ts;
    static __thread uint16_t r_num;
    //tx_id is a value from dns record, it has 2 bytes so there is 0-65535 possible values
    //array which contains timestamps of query packet for specific tx_id
    static __thread uint64_t tx_times[65536];
    //array which contains uri_or_ip of query packet for specific tx_id
    static __thread char tx_r_uri[65536][100];

    if ( nn_init_dns == 0 ) {
        nn_init_dns = 1;
        NanomsgInit(&nn_handler_dns, nanomsg_url_dns, sizeof(DNSData), DNS_RECORDS);
    }

    //DNS transaction
    DNSData* dns = (DNSData*)NanomsgGetNextBufferElement(&nn_handler_dns);
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
    dns->tx_rcode = tx->rcode;
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

    if (NULL != p->flow)
        dns->flow_id = p->flow->flowInfo.flow_id;
    else
        dns->flow_id = 0;

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
}
//#COLLECTIVE_SENSE_END #DNS

#endif
