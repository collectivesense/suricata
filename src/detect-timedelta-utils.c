#include "detect-timedelta-utils.h"
#include "detect-timedelta-common.h"
#include "detect-timedelta-logger.h"

////////////////////////////////////////////////////////////////////////////////
//
// TIME FUNCTIONS
//
////////////////////////////////////////////////////////////////////////////////

    __thread TimeInMicroSec g_current_time;    // in order to avoid expensive time() syscall, we keep track of latest time by extracting it from packets and storing it here for future use

    void UpdateCurrentTime( TimeInMicroSec now, FlowId flow_id )
    {
        if( now > g_current_time )  // new packet should have >= timestamp than last
        {
            g_current_time = now;
        }
        else
        {
            TDLogWarning( flow_id, 0, "Warning: packet with an older timestamp received!" );             // received a back-to-the-future packet :)

            // if for some reason Suricata's timestamping sporadically would malfunction and report very futuristic timestamps,
            // it would cause all flows to potenitally expire prematurely.  In order words, it would render this plugin useless,
            // thus this warning is very important.  TODO perhaps add some mechanism to alleviate this risk?

            // for now let's SCREAM if the difference is bigger than 10 seconds
            if( now - g_current_time > 10*MILLION )
            {
                TDLogError( flow_id, 0, "Warning: Officially this packet is over 10 seconds old!  NOTE that this might mean that this packet's timestamp is actually correct, but some previous packet was with a future timestamp" );
                //assert(0);
            }

        }
    }






////////////////////////////////////////////////////////////////////////////////
//
// PACKET LOGGING
//
////////////////////////////////////////////////////////////////////////////////

    static inline FlowId GetFlowIdFromPacket( Packet* packet )
    {
        return (FlowId) packet->flow;
    }

    static inline void DecodeTcpFlags( char output[9], uint8_t tcp_flags )
    {
        *output++ = (tcp_flags & TH_CWR)  ? 'C' : '.';
        *output++ = (tcp_flags & TH_ECN)  ? 'E' : '.';
        *output++ = (tcp_flags & TH_URG)  ? 'U' : '.';
        *output++ = (tcp_flags & TH_ACK)  ? 'A' : '.';
        *output++ = (tcp_flags & TH_PUSH) ? 'P' : '.';
        *output++ = (tcp_flags & TH_RST)  ? 'R' : '.';
        *output++ = (tcp_flags & TH_SYN)  ? 'S' : '.';
        *output++ = (tcp_flags & TH_FIN)  ? 'F' : '.';
        *output = 0;    // string terminator
    }

    static inline void LogPacketPayload( Packet* packet )
    {
        #ifdef TD_DEBUG

         FlowId flow_id = GetFlowIdFromPacket( packet );

         int32_t len = packet->payload_len;

         // limit payload logging to something sane but yet useful
         const int32_t MAX_LEN = 15;     // leave one byte for 0-terminator
         if( len > MAX_LEN )
             len = MAX_LEN;

         // copy buffer
         char    payload[MAX_LEN+1];
         memcpy( &payload, packet->payload, len );
         payload[len] = 0;   // string terminator in case it's needed

         // trim trailing \n and/or \r (for pretty logging purposes)
         while( --len >= 0 ) {
             if( payload[len] == '\n' || payload[len] == '\r' )
                 payload[len] = 0;
             else
                 break;
         }

         TDLogInfo( flow_id, 0, "Packet payload: [%u]                                                 >%s<", packet->payload_len, (len ? payload : "") );

        #endif
    }

    static inline void LogPacketHeader( Packet* packet )
    {
        FlowId flow_id = GetFlowIdFromPacket( packet );

        if( packet->tcph == NULL )
        {
            TDLogError( flow_id, 0, "WTF! packet->tcph is NULL!" );
            return;
        }
        TCPHdr header = *( packet->tcph );

        // log direction, SEQ and ACK numbers
        uint32_t dst_addr = ntohl( *(uint32_t*) &(packet->dst.address) );
        uint32_t src_addr = ntohl( *(uint32_t*) &(packet->src.address) );
        TDLogInfo( flow_id, 0, "ports: %hu -> %hu, seq: %u ack: %u, IPs: %u -> %u", ntohs(header.th_sport), ntohs(header.th_dport), ntohl(header.th_seq), ntohl(header.th_ack), src_addr, dst_addr);

        // log TCP flags
        char flags[9];
        DecodeTcpFlags( flags, header.th_flags );
        TDLogInfo( flow_id, 0, "tcp flags: %u %s", header.th_flags, flags );
    }

    static inline void LogPacketTimestamp( Packet* packet )
    {
        FlowId flow_id = GetFlowIdFromPacket( packet );


        TDLogInfo( flow_id, 0, "packet->ts:           %lu.%06lu", packet->ts.tv_sec, packet->ts.tv_usec );

    }

    void LogPacket( Packet* packet )
    {
        FlowId flow_id = GetFlowIdFromPacket( packet );

        TDLogInfo( flow_id, 0, "-------------------[PACKET]-------------------" );
        LogPacketHeader( packet );
        LogPacketTimestamp( packet );
        LogPacketPayload( packet );
        TDLogInfo( flow_id, 0, "--" );
    }



