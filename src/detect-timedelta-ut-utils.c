#include "detect-timedelta-ut-utils.h"

void UTH_FillPacket( Packet* packet, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint8_t tcp_flags, const char* payload )
{
    // bacause Packet normally needs to have a TCPHdr dynamically allocated, here we cheat:
    // we pre-allocate TCPHdr's and deal them out to packets.  Unless your unit test function uses
    // more packets than the number of headers we allocated here (64), there shouldn't be a problem.
    // (note: alternatively, we could just malloc() those headers and not worry about memleaks, just like we do for payload)
    static int headers_allocated = 0;
    static TCPHdr tcp_headers[64];
    packet->tcph = &tcp_headers[headers_allocated++ % 64];

    // TCP flags
    packet->tcph->th_flags = tcp_flags;

    // source and destination
    packet->src.address.address_un_data32[0] = src_ip;
    packet->dst.address.address_un_data32[0] = dst_ip;
    packet->sp = src_port;
    packet->dp = dst_port;

    // payload length
    packet->payload_len = strlen( payload );

    // timestamps will automatically increase by 1 second
    static uint32_t seconds = 1234500000;
    packet->ts.tv_sec  = ++seconds;
    packet->ts.tv_usec =    654321;

    // packets by default will have correct acks assuming they're initialised in flow order.
    // sequence numbers will automatically increase per TCP rules, and ack numbers will always equal expected seq numbers
    static uint32_t IP1_seq = 1000;
    static uint32_t IP2_seq = 2000;
    if( src_ip == TEST_IP_1 ) {
        packet->tcph->th_seq = htonl( IP1_seq );
        packet->tcph->th_ack = htonl( IP2_seq );
        IP1_seq += (tcp_flags & TH_SYN) ? 1 : packet->payload_len;
    } else {
        packet->tcph->th_seq = htonl( IP2_seq );
        packet->tcph->th_ack = htonl( IP1_seq );
        IP2_seq += (tcp_flags & TH_SYN) ? 1 : packet->payload_len;
    }

    #ifdef TD_DEBUG
     packet->payload = malloc( 4096 );      // it's just a unit test, who cares about memleaks
     strncpy( (char*) packet->payload, payload, 4095 );
     packet->payload[4095] = 0;
    #endif

    // need this so that LogPacketTimestamp() doesn't segfault
    static Flow flow;
    flow.startts = packet->ts;
    flow.lastts  = packet->ts;
    packet->flow = &flow;

    LogPacket( packet );
}

