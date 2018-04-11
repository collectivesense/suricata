//CS - COLLECTIVE-SENSE extension code property
#pragma once

#define RTP_VERSION 2
#define RTCP_SR 200
#define RTCP_RR 201
#define RTCP_HEADER_SIZE 4

typedef struct RTCPReportBlock_ {
    uint32_t ssrc_id;
    uint32_t fraction_lost:8;
    uint32_t cum_num_packets_lost:24;
    uint16_t seq_num_cycles_count;
    uint16_t hi_seq_num_recv;
    uint32_t interarr_jitter;
    uint32_t last_sr_ts;
    uint32_t delay_since_last_sr_ts;
}
RTCPReportBlock;

typedef struct RTCPSenderReport_ {
    uint32_t ssrc;
    uint32_t ts_msw;
    uint32_t ts_lsw;
    uint32_t ts_rtp;
    uint32_t snd_p_count;
    uint32_t snd_o_count;

    RTCPReportBlock sender_rb;
}
RTCPSenderReport;

typedef struct RTCPReceiverReport_ {
    uint32_t ssrc;
    RTCPReportBlock receiver_rb;
}
RTCPReceiverReport;

typedef struct RTCPSourceDescription_ {
    uint32_t ssrc_id;
    uint8_t  sdes_type;
    uint8_t  sdes_length;
    uint8_t  sdes_text[65];
    uint8_t  sdes_type2;
}
RTCPSourceDescription;

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     BT=6      |L|D|J|ToH|rsvd.|       block length = 9        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        SSRC of source                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          begin_seq            |             end_seq           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        lost_packets                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        dup_packets                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         min_jitter                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         max_jitter                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         mean_jitter                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         dev_jitter                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | min_ttl_or_hl | max_ttl_or_hl |mean_ttl_or_hl | dev_ttl_or_hl |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
typedef struct RTCPXRStats_ {
    uint32_t ssrc;
    uint8_t block_type;
    uint8_t flags:5;
    uint8_t reserved:3;
    uint16_t block_length;
    uint32_t ssrc_id;
    uint16_t begin_seq;
    uint16_t end_seq;
    uint32_t lost_packets;
    uint32_t dup_packets;
    uint32_t min_jitter;
    uint32_t max_jitter;
    uint32_t mean_jitter;
    uint32_t dev_jitter;
    uint8_t min_ttl_or_hl;
    uint8_t max_ttl_or_hl;
    uint8_t mean_ttl_or_hl;
    uint8_t dev_ttl_or_hl;
}
RTCPXRStats;

//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     BT=7      |   reserved    |       block length = 8        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        SSRC of source                         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |   loss rate   | discard rate  | burst density |  gap density  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |       burst duration          |         gap duration          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     round trip delay          |       end system delay        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | signal level  |  noise level  |     RERL      |     Gmin      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |   R factor    | ext. R factor |    MOS-LQ     |    MOS-CQ     |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |   RX config   |   reserved    |          JB nominal           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          JB maximum           |          JB abs max           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
typedef struct RTCPXRMetrics_ {
    uint32_t ssrc;
    uint8_t block_type;
    uint8_t reserved1;
    uint16_t block_length;
    uint32_t ssrc_id;
    uint8_t loss_rate;
    uint8_t discard_rate;
    uint8_t burst_density;
    uint8_t gap_density;
    uint16_t burst_duration;
    uint16_t gap_duration;
    uint16_t round_trip_delay;
    uint16_t end_system_delay;
    uint8_t signal_level;
    uint8_t noise_level;
    uint8_t rerl;
    uint8_t gmin;
    uint8_t r_factor;
    uint8_t ext_r_factor;
    uint8_t mos_lq;
    uint8_t mos_cq;
    uint8_t rx_config;
    uint8_t reserved2;
    uint16_t jb_nominal;
    uint16_t jb_maximum;
    uint16_t jb_abs_max;
}
RTCPXRMetrics;

typedef struct RTCPPacket_ {
    //RTCP common header
    uint8_t version:2;
    uint8_t padding:1;
    uint8_t rc:5;
    uint8_t type;
    uint8_t block_type;
    uint16_t length;

    union {
        RTCPSenderReport sr;
        RTCPReceiverReport rr;
        RTCPSourceDescription sd;
        RTCPXRStats xrs;
        RTCPXRMetrics xrm;
    } r;
}
RTCPPacket;

uint32_t rtcp_decode_sr(const uint8_t *payload, const uint32_t len, const uint32_t start, RTCPSenderReport* sr);
uint32_t rtcp_decode_sd(const uint8_t *payload, const uint32_t len, const uint32_t start, RTCPSourceDescription* sd);
uint32_t rtcp_decode_xrs(const uint8_t *payload, const uint32_t len, const uint32_t start, RTCPXRStats* xrs);
uint32_t rtcp_decode_xrm(const uint8_t *payload, const uint32_t len, const uint32_t start, RTCPXRMetrics* xrm);
uint32_t rtcp_decode_report_blocks(const uint8_t *payload, const uint32_t len, const uint32_t start, const uint32_t end, RTCPReportBlock* rbs);
uint8_t is_rtcp_packet(const unsigned char *payload, const uint16_t len);

///////////

uint32_t rtcp_decode_sr(const uint8_t *payload, const uint32_t len, const uint32_t start, RTCPSenderReport* sr) {
    uint32_t i = start;

    if (i >= len) {
        printf("[rtcp_decode_sr] Wrong index or packet len\n");
        return 0;
    }

    sr->ssrc = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i += 4;
    sr->ts_msw = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i += 4;
    sr->ts_lsw = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i += 4;
    sr->ts_rtp = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i += 4;
    sr->snd_p_count = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i += 4;
    sr->snd_o_count = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i += 4;

    return i - start;
}

uint32_t rtcp_decode_sd(const uint8_t *payload, const uint32_t len, const uint32_t start, RTCPSourceDescription* sd) {
    uint32_t i = start;

    if (i >= len) {
        printf("[rtcp_decode_sd] Wrong index or packet len\n");
        return 0;
    }

    sd->ssrc_id = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i += 4;
    sd->sdes_type = payload[i++];
    sd->sdes_length = payload[i++];
    size_t sdes_text_len = sizeof(sd->sdes_text) > sd->sdes_length ? sd->sdes_length : sizeof(sd->sdes_text);
    memcpy(sd->sdes_text, payload + i, sdes_text_len);
    sd->sdes_text[sdes_text_len-1] = '\0';
    i += sdes_text_len;
    sd->sdes_type2 = payload[i++];

    return i - start;
}

uint32_t rtcp_decode_report_blocks(const uint8_t *payload, const uint32_t len, const uint32_t start, const uint32_t end, RTCPReportBlock* rbs) {
    //internal loop with report blocks

    //printf ("start: %u, end: %u, len: %u\n", start, end, len);

    uint32_t bytes_read = 0;
    for ( uint32_t i = start; i < end && i + sizeof(RTCPReportBlock) <= len; ) {

        rbs->ssrc_id = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
        i += 4;
        rbs->fraction_lost = payload[i++];
        rbs->cum_num_packets_lost = payload[i] << 16 | payload[i+1] << 8 | payload[i+2];
        i += 3;
        rbs->seq_num_cycles_count = payload[i] << 8 | payload[i+1];
        i += 2;
        rbs->hi_seq_num_recv = payload[i] << 8 | payload[i+1];
        i += 2;
        rbs->interarr_jitter = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
        i += 4;
        rbs->last_sr_ts = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
        i += 4;
        rbs->delay_since_last_sr_ts = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
        i += 4;

        bytes_read = i - start;
    }

    return bytes_read;
}

uint32_t rtcp_decode_xrs(const uint8_t *payload, const uint32_t len, const uint32_t start, RTCPXRStats* xrs) {
    uint32_t i = start;

    if (i >= len) {
        printf("[rtcp_decode_xrs] Wrong index or packet len\n");
        return 0;
    }

    xrs->block_type = payload[i++];
    xrs->flags = payload[i] >> 3;
    xrs->reserved = 0; i++;
    xrs->block_length = payload[i] << 8 | payload[i+1];
    i+=2;
    xrs->ssrc_id = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i+=4;
    xrs->begin_seq = payload[i] << 8 | payload[i+1];
    i+=2;
    xrs->end_seq = payload[i] << 8 | payload[i+1];
    i+=2;
    xrs->lost_packets = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i+=4;
    xrs->dup_packets = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i+=4;
    xrs->min_jitter = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i+=4;
    xrs->max_jitter = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i+=4;
    xrs->mean_jitter = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i+=4;
    xrs->dev_jitter = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i+=4;
    xrs->min_ttl_or_hl = payload[i++];
    xrs->max_ttl_or_hl = payload[i++];
    xrs->mean_ttl_or_hl = payload[i++];
    xrs->dev_ttl_or_hl = payload[i++];

    return i - start;
}

uint32_t rtcp_decode_xrm(const uint8_t *payload, const uint32_t len, const uint32_t start, RTCPXRMetrics* xrm) {
    uint32_t i = start;

    if (i >= len) {
        printf("[rtcp_decode_xrm] Wrong index or packet len\n");
        return 0;
    }
    xrm->block_type = payload[i++];
    xrm->reserved1 = 0; i++;
    xrm->block_length = payload[i] << 8 | payload[i+1];
    i+=2;
    xrm->ssrc_id = payload[i] << 24 | payload[i+1] << 16 | payload[i+2] << 8 | payload[i+3];
    i+=4;
    xrm->loss_rate = payload[i++];
    xrm->discard_rate = payload[i++];
    xrm->burst_density = payload[i++];
    xrm->gap_density = payload[i++];
    xrm->burst_duration = payload[i] << 8 | payload[i+1];
    i+=2;
    xrm->gap_duration = payload[i] << 8 | payload[i+1];
    i+=2;
    xrm->round_trip_delay = payload[i] << 8 | payload[i+1];
    i+=2;
    xrm->end_system_delay = payload[i] << 8 | payload[i+1];
    i+=2;
    xrm->signal_level = payload[i++];
    xrm->noise_level = payload[i++];
    xrm->rerl = payload[i++];
    xrm->gmin = payload[i++];
    xrm->r_factor = payload[i++];
    xrm->ext_r_factor = payload[i++];
    xrm->mos_lq = payload[i++];
    xrm->mos_cq = payload[i++];
    xrm->rx_config = payload[i++];
    xrm->reserved2 = 0; i++;
    xrm->jb_nominal = payload[i] << 8 | payload[i+1];
    i+=2;
    xrm->jb_maximum = payload[i] << 8 | payload[i+1];
    i+=2;
    xrm->jb_abs_max = payload[i] << 8 | payload[i+1];
    i+=2;

    return i - start;
}

//uint8_t is_rtcp_header(const uint8_t *payload, const uint16_t len) {
//    if ( len > 2 && ((payload[0] << 8 | payload[1]) & RTCP_VALID_MASK) == RTCP_VALID_VALUE )
//        return 1;
//
//    return 0;
//}

uint8_t is_rtcp_packet(const unsigned char *payload, const uint16_t len) {
    if ( !(len > 2) || payload == NULL )
        return 0;

    if (
        (
            (((payload[0] >> 6) & 3) != RTP_VERSION) &&         // version
            (((payload[0] >> 6) & 3) != 1)
        )
        || ((payload[0] & 0x20) != 0)                           // padding in first packet
        || ((payload[1] != RTCP_SR) && (payload[1] != RTCP_RR)) // first rtcp item SR or RR
    ) {
        return 0;
    }

    const unsigned char *end = payload + len;

    do {
        //go to next subpacket
        payload += (((payload[2] << 8) | payload[3]) + 1) * 4;
    } while (payload < end && (((payload[0] >> 6) & 3) == RTP_VERSION));

    return payload == end;
}
