#pragma once

#include "detect-timedelta-common.h"

// config
#define               FLOWINFO_NUM_OF_PACKETS      6    // T1..T6
#define               FLOWINFO_NUM_OF_OOOPACKETS   15   // unclassiffied (out of order) packets
#define               FLOWINFO_NUM_OF_PREVPACKETS  5   //

typedef struct FlowInfo_ FlowInfo;
typedef uint64_t TimeInMicroSec;

typedef struct Endpoints_
{
    uint32_t src_ip[4];
    uint32_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
}
Endpoints;

typedef enum PacketType_
{
    PT_NULL = 0,    // packet not available (we use this when packet hasn't come in yet)
    PT_DIR_CS,      // client --> server, aka request
    PT_DIR_SC,      // server --> client, aka response
    PT_UNRELATED,   // packet not belonging to current flow
    PT_UNDETERMINED // packet direction not known yet (PacketType inside OooPacket use this, but only for a brief while. Once packet direction is known (as a result of SYN showing up and clarifying which direction is which), this may get replaced with appropriate PT_DIR_SC or PT_DIR_CS)
}
PacketType;

typedef struct PacketInfo_
{
    PacketType      packet_type;    // set to PT_NULL when packet not available
    uint8_t         tcp_flags;
    TimeInMicroSec  timestamp;
    uint32_t        seq_num;
    uint32_t        ack_num;
    // payload
    uint32_t        payload_len;
}
PacketInfo;

typedef struct PacketExtInfo_
{
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    Address src;
    Address dst;
    union {
        Port sp;
        uint8_t type;
    };
    union {
        Port dp;
        uint8_t code;
    };
    uint8_t proto;

    struct Flow_ *flow;

    /* raw hash value for looking up the flow, will need to modulated to the
     * hash size still */
    uint32_t flow_hash;

    struct timeval ts;

    /* header pointers */
    EthernetHdr ethh;

    IPV4Hdr ip4h;
    IPV6Hdr ip6h;

    TCPHdr tcph;
    UDPHdr udph;

    /* ptr to the payload of the packet with it's length. */
    //uint8_t *payload;
    uint16_t payload_len;
}
PacketExtInfo;

typedef struct OooPacket_
{
    // OooPacket requires some explanation.  If the world were ideal, packets would always be read from NIC in chronological order.
    // Unfortunately, sometimes that's not the case.  So when that happens, we need to store the out-of-order packets temporarily somewhere
    // on the side, until we can reassemble the order and process them.  That's what this struct is for.  Any out-of-order packets we keep
    // on the side, we keep in form of OooPacket's, until it is time to process them.  As you can see, it contains mostly fragments of
    // struct Packet along with endpoint information which will be needed until the proper packet flow can be reconstructed.

    // src and dst
    Endpoints  ep;
    PacketType packet_type;

    // TCP header
    uint8_t  th_flags;
    uint32_t th_seq;
    uint32_t th_ack;

    // timestamp
    struct timeval ts;

    // payload
    uint16_t payload_len;
}
OooPacket;

typedef struct FlowInfo_
{
    // DO NOT MOVE THIS FIELD!!! It must be the first field - hashtable semantics rely on this
    FlowId      flow_id;    // Suricata's flow_id

    Endpoints   ep;

    PacketInfo  packets[FLOWINFO_NUM_OF_PACKETS];   // packets for T1 - T6
    size_t      processed_packets;                  // which (CONSECUTIVE from T1) packet we're expecting next (or alternatively, how many (CONSECUTIVE starting from T1) T packets we already collected).  We always start with 0, and as we receive T1, T2, T3, etc, this number keeps getting incremented.  So if we already received T1, T2 and T4, this number would be set to 2 and would jump to 4 after T3 arrives

    OooPacket   ooo_packets[FLOWINFO_NUM_OF_OOOPACKETS];  // ptr to an array of OooPacket's.  Allocated only when needed, as the usual case is for packets to arrive in order
    size_t      ooo_packets_cnt;

    int (*flowInfoFree)(FlowInfo*);

    char log_state;

    //uint32_t    current_ack;
    //uint32_t    current_seq;

    PacketExtInfo prev_packets[FLOWINFO_NUM_OF_PREVPACKETS];
    //current id in prev_packets array
    uint8_t pp_cur_id;
    //previous id in prev_packets array
    uint8_t pp_id;

    //timestamp val from the last packet
    uint64_t p_ts;
    //internal packet id in the flow...
    uint64_t p_id;
}
FlowInfo;