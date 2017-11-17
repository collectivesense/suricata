//CS - COLLECTIVE-SENSE extension code property
#pragma once

// Suricata" //Packet struct definition
#include "decode.h"

// our plugin
#include <cs/cscommon.h>
#include "detect-nanomsg.h"
#include "decode-rtcp.h"

#define BUF_SIZE_RTCP sizeof(RTCPData) * 1
void RTCPCapture(const Packet* packet) {
    static __thread NanomsgHandler nn_handler_rtcp;
    static __thread char nn_init_rtcp = 0;

    const uint8_t *payload = packet->payload;
    const uint16_t len = packet->payload_len;

    if( nn_init_rtcp == 0 ) {
        nn_init_rtcp = 1;
        NanomsgInit(&nn_handler_rtcp, nanomsg_url_rtcp, BUF_SIZE_RTCP);
    }

    int i = 0;
    while (i + RTCP_HEADER_SIZE < len) {
        uint32_t offset = i;

        // decode RTCP header
        RTCPPacket rtcp_p;
        memset(&rtcp_p, 0, sizeof(RTCPPacket));
        rtcp_p.version   = (payload[i] >> 6);
        rtcp_p.padding   = (payload[i] & 0x20) >> 5;
        rtcp_p.rc        = (payload[i] & 0x1F);
        rtcp_p.type      = payload[++i];
        rtcp_p.length    = (payload[i+1] << 8) | payload[i+2];
        i += 3;

        uint8_t valid_values = 0;

        //take memory only when we support this type of RTCP packet
        if ( rtcp_p.type != (uint8_t)RTCP_SENDER_REPORT && rtcp_p.type != (uint8_t)RTCP_RECEIVER_REPORT && rtcp_p.type != (uint8_t)RTCP_XR ) {

            //when we do not support some types of rtcp protocols we have to skip them...
            //printf ("THIS IS RTCP JUMP - NOT SUPPORTED PACKET TYPE\n");
            i += (int)rtcp_p.length * 4;
            continue;
        }

        uint32_t rtcp_bytes_length = RTCP_HEADER_SIZE + (uint32_t)rtcp_p.length * 4; // rtcp header + rtcp_payload

        if ( rtcp_p.type == (uint8_t) RTCP_SENDER_REPORT ) {
            //printf ("THIS IS RTCP_SENDER_REPORT\n");
            //first decode rtcp sender info part
            i += rtcp_decode_sr(payload, len, i, &rtcp_p.r.sr);

            //decode rtcp sender report(s) - second part
            i += rtcp_decode_report_blocks(payload, len, i, offset + rtcp_bytes_length, &rtcp_p.r.sr.sender_rb);

            valid_values = 1;
        } else if (rtcp_p.type == (uint8_t) RTCP_RECEIVER_REPORT) {
            //printf ("THIS IS RTCP_RECEIVER_REPORT\n");
            rtcp_p.r.rr.ssrc = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
            i += 4;

            i += rtcp_decode_report_blocks(payload, len, i, offset + rtcp_bytes_length, &rtcp_p.r.rr.receiver_rb);
            valid_values = 1;
        // } else if (rtcp_p.type == (uint8_t) RTCP_SOURCE_DESCRIPTION) {
        //     printf ("THIS IS RTCP_SOURCE_DESCRIPTION\n");
        //     i += rtcp_decode_sd(payload, len, i, &rtcp_p.r.sd);
        //     ...
        } else if ( rtcp_p.type == (uint8_t)RTCP_XR) {
            uint32_t tmp_ssrc = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
            i+=4;
            rtcp_p.block_type = payload[i];

            if ( rtcp_p.block_type == (uint8_t) RTCP_XR_STATISTICS) {
                // printf ("THIS IS RTCP_XR_STATISTICS PACKET\n");
                rtcp_p.r.xrs.ssrc = tmp_ssrc;

                i += rtcp_decode_xrs(payload, len, i, &rtcp_p.r.xrs);
                valid_values = 1;
            } else if ( rtcp_p.block_type == (uint8_t) RTCP_XR_METRICS) {
                // printf ("THIS IS RTCP_XR_METRICS PACKET\n");
                rtcp_p.r.xrm.ssrc = tmp_ssrc;

                i += rtcp_decode_xrm(payload, len, i, &rtcp_p.r.xrm);
                valid_values = 1;
            }
        }

        //send message only when you have rtcp packet
        //we can not free just single packet (if this packet is not a valid rtcp) when we allocate bigger buffer
        //so that we need to copy whole packet here to the buffer
        if (valid_values > 0) {

            RTCPData* rtcpd = (RTCPData*)NanomsgGetNextBufferElement(&nn_handler_rtcp, sizeof(RTCPData));
            //memset(rtcpd, 0, sizeof(RTCPData));
            //this is common data for every RTCP packet (even in the same UDP packet) but for simple solution it is repeated
            //... because we do not know how many RTCP packets is inside one UDP packet
            //dynamic buffor/protocol is the right solution... some day
            rtcpd->ts = GetTimestampInMicroSec(packet->ts);
            SetIp_NET32_TO_HOST64(GET_IPV4_SRC_ADDR_PTR(packet), rtcpd->src_ip);
            SetIp_NET32_TO_HOST64(GET_IPV4_DST_ADDR_PTR(packet), rtcpd->dst_ip);
            rtcpd->src_port = packet->sp;
            rtcpd->dst_port = packet->dp;

            RTCPDataPacket* rtcpd_p = &rtcpd->rtcp_data_packets[0];
            rtcpd_p->type = rtcp_p.type;

            if ( rtcp_p.type == (uint8_t)RTCP_SENDER_REPORT ) {
                rtcpd_p->r.sr.ssrc                     = rtcp_p.r.sr.ssrc;
                rtcpd_p->r.sr.snd_p_count              = rtcp_p.r.sr.snd_p_count;
                rtcpd_p->r.sr.rdp.ssrc_id              = rtcp_p.r.sr.sender_rb.ssrc_id;
                rtcpd_p->r.sr.rdp.fraction_lost        = rtcp_p.r.sr.sender_rb.fraction_lost;
                rtcpd_p->r.sr.rdp.cum_num_packets_lost = rtcp_p.r.sr.sender_rb.cum_num_packets_lost;
                rtcpd_p->r.sr.rdp.interarr_jitter      = rtcp_p.r.sr.sender_rb.interarr_jitter;

            } else if ( rtcp_p.type == (uint8_t)RTCP_RECEIVER_REPORT ) {
                rtcpd_p->r.rr.ssrc                     = rtcp_p.r.rr.ssrc;
                rtcpd_p->r.rr.rdp.ssrc_id              = rtcp_p.r.rr.receiver_rb.ssrc_id;
                rtcpd_p->r.rr.rdp.fraction_lost        = rtcp_p.r.rr.receiver_rb.fraction_lost;
                rtcpd_p->r.rr.rdp.cum_num_packets_lost = rtcp_p.r.rr.receiver_rb.cum_num_packets_lost;
                rtcpd_p->r.rr.rdp.interarr_jitter      = rtcp_p.r.rr.receiver_rb.interarr_jitter;

            // } else if (rtcp_p.type == (uint8_t)RTCP_SOURCE_DESCRIPTION ) {
            //     ...
            } else if ( rtcp_p.type == (uint8_t)RTCP_XR ) {

                rtcpd_p->xr_type = rtcp_p.block_type;

                if ( rtcp_p.block_type == (uint8_t)RTCP_XR_STATISTICS) {
                    rtcpd_p->r.xrs.ssrc         = rtcp_p.r.xrs.ssrc;
                    rtcpd_p->r.xrs.ssrc_id      = rtcp_p.r.xrs.ssrc_id;
                    rtcpd_p->r.xrs.lost_packets = rtcp_p.r.xrs.lost_packets;
                    rtcpd_p->r.xrs.dup_packets  = rtcp_p.r.xrs.dup_packets;
                    rtcpd_p->r.xrs.min_jitter   = rtcp_p.r.xrs.min_jitter;
                    rtcpd_p->r.xrs.mean_jitter  = rtcp_p.r.xrs.mean_jitter;
                    rtcpd_p->r.xrs.max_jitter   = rtcp_p.r.xrs.max_jitter;

                } else if ( rtcp_p.block_type == (uint8_t)RTCP_XR_METRICS ) {
                    rtcpd_p->r.xrm.ssrc         = rtcp_p.r.xrm.ssrc;
                    rtcpd_p->r.xrm.ssrc_id      = rtcp_p.r.xrm.ssrc_id;
                    rtcpd_p->r.xrm.loss_rate    = rtcp_p.r.xrm.loss_rate;
                    rtcpd_p->r.xrm.discard_rate = rtcp_p.r.xrm.discard_rate;
                    rtcpd_p->r.xrm.signal_level = rtcp_p.r.xrm.signal_level;
                    rtcpd_p->r.xrm.noise_level  = rtcp_p.r.xrm.noise_level;
                    rtcpd_p->r.xrm.mos_lq       = rtcp_p.r.xrm.mos_lq;
                    rtcpd_p->r.xrm.mos_cq       = rtcp_p.r.xrm.mos_cq;
                }
            }

            NanomsgSendBufferIfNeeded(&nn_handler_rtcp);
        }

        valid_values = 0;
    };
}

////////////////////////////////////////////////////////////////////////////////
//
// PACKETHEADERS CAPTURE
//
////////////////////////////////////////////////////////////////////////////////

static METRIC_ID ph_metric_id = 0;

// brief Regex for parsing our keyword options
#define PARSE_REGEX  "^\\s*([^\\s]+)?\\s*,s*([0-9]+)?\\s*$"
static pcre*        parse_regex;
static pcre_extra*  parse_regex_study;

// some forward declarations
static int  DetectTimeDeltaMatch( ThreadVars*, DetectEngineThreadCtx*, Packet*, Signature*, SigMatch* );
static int  DetectTimeDeltaSetup( DetectEngineCtx*, Signature*, char* );
static void DetectTimeDeltaFree ( void* );
static void DetectTimeDeltaRegisterTests();
static void RegisterSigmatchTable();
static void CompileRegex();
static void SanityCheck();

#define CMP_ETH_DS(p, pp) \
    (((pp)->eth_dst[0] == (p)->eth_src[0] && \
      (pp)->eth_dst[1] == (p)->eth_src[1] && \
      (pp)->eth_dst[2] == (p)->eth_src[2] && \
      (pp)->eth_dst[3] == (p)->eth_src[3] && \
      (pp)->eth_dst[4] == (p)->eth_src[4] && \
      (pp)->eth_dst[5] == (p)->eth_src[5] ))

void copy_packet_to_ext_packet(const Packet* p, uint8_t pp_cur_id)
{
    //printf("pp_cur_id: %d\n",pp_cur_id);

    PacketExtInfo* pe = &p->flow->flowInfo.prev_packets[pp_cur_id];
    if (pe == NULL) {
        printf("PE IS NULL");
        return;
    }

    pe->src = p->src;
    pe->dst = p->dst;
    pe->sp = p->sp;
    pe->dp = p->dp;

    pe->proto = p->proto;

    pe->flow = p->flow;
    pe->flow_hash = p->flow_hash;

    pe->ts = p->ts;

    if (p->ethh != NULL)
        pe->ethh = *p->ethh;

    if (p->ip4h != NULL)
        pe->ip4h = *p->ip4h;
    // else
    //     pe->ip4h = NULL;

    if (p->ip6h != NULL)
        pe->ip6h = *p->ip6h;
    // else
    //     pe->ip6h = NULL;

    if (p->tcph != NULL)
        pe->tcph = *p->tcph;
    // else
    //     pe->tcph = NULL;

    if (p->udph != NULL)
        pe->udph = *p->udph;
    // else
    //     pe->udph = NULL;

    pe->payload_len = p->payload_len;
}

char compare_packet_with_packet_ext(const Packet* packet, const PacketExtInfo* packet_ext) {
    if (CMP_ADDR(&packet->src, &packet_ext->src) &&
        CMP_ADDR(&packet->dst, &packet_ext->dst) &&
        CMP_PORT(packet->sp, packet_ext->sp) &&
        CMP_PORT(packet->dp, packet_ext->dp) &&
        packet->payload_len == packet_ext->payload_len &&
        packet->tcph->th_seq == packet_ext->tcph.th_seq &&
        packet->tcph->th_ack == packet_ext->tcph.th_ack &&
        packet->tcph->th_flags == packet_ext->tcph.th_flags &&
        packet->tcph->th_sum == packet_ext->tcph.th_sum
    ) {
        return 1;
    } else
        return 0;
}

void PacketTSValidationAndFix(Packet* packet) {
    if (packet->flow == NULL)
        return;

    if (packet->flow->flowInfo.flow_id != packet->flow->flow_hash) {
        packet->flow->flowInfo.flow_id = packet->flow->flow_hash;
        packet->flow->flowInfo.p_id = 0;
    } else {
        ++packet->flow->flowInfo.p_id;
    }

    if (packet->flow->flowInfo.p_ts == GetTimestampInMicroSec(packet->ts)) {
        ++packet->flow->flowInfo.p_ts;
        packet->ts.tv_sec = packet->flow->flowInfo.p_ts / 1000000;
        packet->ts.tv_usec = packet->flow->flowInfo.p_ts % 1000000;
        //packet->ts.tv_sec = packet->flow->flowInfo.p_ts / 1000000000;
        //packet->ts.tv_usec = packet->flow->flowInfo.p_ts % 1000000000;
    } else {
        packet->flow->flowInfo.p_ts = GetTimestampInMicroSec(packet->ts);
    }
}

//#define URL_PH "ipc:///tmp/packetheaders-pipeline.ipc"
#define BUF_SIZE_PH sizeof(PacketHeaderData) * 10
void PacketHeaderCapture(const Packet* packet)
{
    static __thread NanomsgHandler nn_handler_ph;
    static __thread char nn_init_ph = 0;

    uint8_t retransmission = 0;

    if (packet->flow != NULL && packet->proto == 6) {

        //printf("packet->flow->flowInfo.pp_cur_id: %d\n", packet->flow->flowInfo.pp_cur_id);
        if (packet->flow->flowInfo.pp_cur_id != packet->flow->flowInfo.pp_id) {
            if (
                packet->flow->flowInfo.prev_packets[packet->flow->flowInfo.pp_id].sp > 0 &&
                compare_packet_with_packet_ext(packet, &packet->flow->flowInfo.prev_packets[packet->flow->flowInfo.pp_id])
            ) {
                //printf("packets are EQUAL\n");
                //lets check eth(s)
                if (CMP_ETH_DS(packet->ethh, &packet->flow->flowInfo.prev_packets[packet->flow->flowInfo.pp_id].ethh)) {
                    return;
                    //printf("THIS IS V_RET\n");
                } else {
                    //printf("THIS IS NORMAL V_RET\n");
                    retransmission = 1;
                }
            }
        }

        copy_packet_to_ext_packet(packet, packet->flow->flowInfo.pp_cur_id);

        packet->flow->flowInfo.pp_id = packet->flow->flowInfo.pp_cur_id;

        if (packet->flow->flowInfo.pp_cur_id + 1 == FLOWINFO_NUM_OF_PREVPACKETS) {
            packet->flow->flowInfo.pp_cur_id = 0;
        } else {
            ++packet->flow->flowInfo.pp_cur_id;
        }
    }

    //workaround for udp fragmented packets - just skip them now
    if(packet->proto == 17 && (packet->sp == 0 || packet->dp ==0) )
        return;

    if (unlikely( nn_init_ph == 0 )) {
        nn_init_ph = 1;
        NanomsgInit(&nn_handler_ph, nanomsg_url_ph, BUF_SIZE_PH);
    }

    PacketHeaderData* ph = (PacketHeaderData*)NanomsgGetNextBufferElement(&nn_handler_ph, sizeof(PacketHeaderData));
    ph->timestamp = GetTimestampInMicroSec(packet->ts);

    SetIp_NET32_TO_HOST64(GET_IPV4_SRC_ADDR_PTR(packet), ph->src_ip);
    SetIp_NET32_TO_HOST64(GET_IPV4_DST_ADDR_PTR(packet), ph->dst_ip);
    ph->src_port = packet->sp;
    ph->dst_port = packet->dp;
    ph->payload_len = packet->payload_len;
    ph->proto = packet->proto;

    ph->ttl = 0;
    ph->ret = retransmission;
    if (PKT_IS_IPV4(packet)) {
        ph->ttl = packet->ip4h->ip_ttl;
    } else if (PKT_IS_IPV6(packet)) {
        ph->ttl = packet->ip6h->s_ip6_hlim;
    } else {
        //printf("this is NOT ip packet\n");
    }

    if (packet->tcph) {
        memcpy( ph->tcp_options, packet->tcp_opts, sizeof(ph->tcp_options) );
        ph->flags = packet->tcph->th_flags;
        ph->seq_num = ntohl( packet->tcph->th_seq );
        ph->ack_num = ntohl( packet->tcph->th_ack );
    } else {
        memset( ph->tcp_options, 0, sizeof(ph->tcp_options) );
        ph->flags = 0;
        ph->seq_num = 0;
        ph->ack_num = 0;
    }

    if (packet->ethh != NULL) {
        memcpy( ph->src_mac, packet->ethh->eth_src, sizeof(ph->src_mac) );
        memcpy( ph->dst_mac, packet->ethh->eth_dst, sizeof(ph->dst_mac) );

        //char macSrcStr[18];
        //snprintf(macSrcStr, sizeof(macSrcStr), "%02x:%02x:%02x:%02x:%02x:%02x", packet->ethh->eth_src[0], packet->ethh->eth_src[1], packet->ethh->eth_src[2], packet->ethh->eth_src[3], packet->ethh->eth_src[4], packet->ethh->eth_src[5]);
        //printf("src_MAC: %s\n", macSrcStr);
        //char macDstStr[18];
        //snprintf(macDstStr, sizeof(macDstStr), "%02x:%02x:%02x:%02x:%02x:%02x", packet->ethh->eth_dst[0], packet->ethh->eth_dst[1], packet->ethh->eth_dst[2], packet->ethh->eth_dst[3], packet->ethh->eth_dst[4], packet->ethh->eth_dst[5]);
        //printf("dst_MAC: %s\n", macDstStr);
    } else {
        memset( ph->src_mac, 0, sizeof(ph->src_mac) );
        memset( ph->dst_mac, 0, sizeof(ph->dst_mac) );
        //printf("ETH is NULL\n");
    }

    // if (packet->flow != NULL) {
    //     ph->flow_hash = packet->flow->flowInfo.flow_id;
    //     ph->p_id = packet->flow->flowInfo.p_id;
    // }

    NanomsgSendBufferIfNeeded(&nn_handler_ph);
    update_metric(ph_metric_id, 1);
}
