#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "suricata-common.h"
#include "conf.h"

#include <cs/cscommon.h>
#include <cs/PeriodicMultipleMetricsCollector.h>
#include "detect-timedelta-processing.h"
#include "detect-timedelta-utils.h"
#include "detect-timedelta-flow.h"
#include "detect-timedelta-objects.h"
#include "detect-nanomsg.h"

//#define URL_TD "ipc:///tmp/pipeline.ipc"
#define BUF_SIZE_TD sizeof(TimedeltaResult) * 5

//TODO something to consider: might want to rely on flow_info->processed_cnt when assessing packets in ProcessPacketT*() instaead of manually checking previous packets for empty

////////////////////////////////////////////////////////////////////////////////
//
// FLOW INFO MANAGEMENT
//
////////////////////////////////////////////////////////////////////////////////

    static int CalculateAndLogResults(FlowInfo*);
    static int PacketHandler_ProcessOooPackets(FlowInfo*);

    static __thread int g_T6noT5mode           = 0;     // special mode triggered by ExpireFlow() to check for T6 in ooo queue due to missing T5

    static int ProcessT6inOooDueToNoT5ifFound( FlowInfo* flow_info )
    {
        // This function facilitates is a bit of special behaviour.  Basically, if no T5 comes in,
        // T6 will be stuck in ooo queue.  So we wait for T5 to arrive, and if it never does,
        // the flow eventually gets expired.
        // But T5 is optional.
        // Therefore when expiring flow, we check if perhaps we don't have that T6 stuck in
        // ooo just because T5 didn't show up, and if we do, we process it.

        if ( g_T6noT5mode != 0 )
        {
            printf("ProcessT6inOooDueToNoT5ifFound - g_T6noT5mode is not 0\n");
            return 0;
        }

        // no point in doing any of this unless we at least processed T4.
        // Also no point, if we already processed T5 and/or T6
        if( flow_info->processed_packets != 4 )
        {
            //printf("ProcessT6inOooDueToNoT5ifFound - flow_info->processed_packets != 4\n");
            return 0;
        }

        // flag the T6noT5 special mode (easier than pushing the flag through many function calls just so ProcessPacketT6() can receive it)
        g_T6noT5mode = 1;

        // process ooo the final time in hope of getting that T6 packet
        int ret = PacketHandler_ProcessOooPackets( flow_info );

        // turn off T6noT5 special mode
        g_T6noT5mode = 0;

        if (ret != 0 && ret != 1)
        {
            // can only process successfully 0 or 1 T6, no?
            return 0;
        }

        // report status
        if( ret == 1 )
        {
            TDLogDebug( flow_info->flow_id, 2, "Found a T6 packet stuck in ooo because we had no T5" );
            return TD_RET_FLAG_USED_T6_WITHOUT_T5;
        }
        else
        {
            return 0;
        }
    }

    int ExpireFlow( FlowInfo* flow_info )
    {
        if (!flow_info->flow_id)
        {
            //printf("ExpireFlow - empty flow...\n");
            return 0;
        }

        TDLogDebug( flow_info->flow_id, 1, "ExpireFlow" );

        // see if there's a T6 packet stuck in ooo array due to no T5 and process it (T5 is optional)
        int recovered_T6 = ProcessT6inOooDueToNoT5ifFound( flow_info );

        // log T data we're after (whatever data we collected up until this point
        //printf("ExpireFlow - > CalculateAndLogResults\n");
        CalculateAndLogResults( flow_info );

        FlowInfo_Dtor( flow_info );

        // flag if we ran into T6 but no T5 situation
        return recovered_T6;
    }

////////////////////////////////////////////////////////////////////////////////
//
// SPECIFIC PACKET PROCESSING
//
////////////////////////////////////////////////////////////////////////////////
    static int ProcessPacketT4(const Packet*, FlowInfo*, PacketType);
    static int ProcessPacketT5(const Packet*, FlowInfo*, PacketType);
    static int ProcessPacketT6(const Packet*, FlowInfo*, PacketType);

    static int ProcessPacketT2( const Packet* packet, FlowInfo* flow_info )
    {
        TDLogDebug( flow_info->flow_id, 1, "ProcessPacketT2() start" );

        // check SYN packet
        if (flow_info->packets[0].packet_type != PT_DIR_CS || flow_info->packets[0].tcp_flags != TH_SYN)
        {
            printf("ProcessPacketT2 - SYN packet is not present\n");
            return 0;
        }

        // if this is SYN+ACK responding to previous SYN
        if( ! PacketInfo_IsEmpty(& flow_info->packets[0])                    &&  // previous packet (#0) was received (SYN packet)
            ntohl(packet->tcph->th_ack) == flow_info->packets[0].seq_num + 1 )   // ack number corresponds to SYN's seq number
        {
            //printf("ProcessPacketT2 - OK!\n");
            return FlowInfo_InitPacket( flow_info, 1, packet, PT_DIR_SC );
        }
        // if this is not it
        else
        {
            //TDLogDebug( flow_info->flow_id, 1, "unhandled SYN+ACK received, abandoning the flow" );
            return 0;
        }
    }

    static int ProcessPacketT3( const Packet* packet, FlowInfo* flow_info, PacketType packet_type )
    {
        TDLogDebug( flow_info->flow_id, 1, "ProcessPacketT3() start" );

        // ACK could be a response to SYN+ACK, or to something else, thus we need to check the case

        // if this is a response to SYN+ACK
        //if( packet_type == PT_DIR_CS                                         && // this packet is client -> server
        if( (packet->flowflags & FLOW_PKT_TOSERVER)                          && // this packet is client -> server
            packet->payload_len == 0                                         && // packet carries no payload
            ! PacketInfo_IsEmpty(& flow_info->packets[1])                    && // previous packet (#1) was received (SYN+ACK packet)
            ntohl(packet->tcph->th_ack) == flow_info->packets[1].seq_num + 1 && // \_ ack and seq numbers correspond
            ntohl(packet->tcph->th_seq) == flow_info->packets[1].ack_num     )  // /  to previous packet's
        {
            //printf("ProcessPacketT3 - OK!\n");
            return FlowInfo_InitPacket( flow_info, 2, packet, PT_DIR_CS );
        }
        // if this is NOT a response to SYN+ACK
        else
        {
            TDLogDebug( flow_info->flow_id, 2, "ACK to something else - forwarding to T4" );
            ProcessPacketT4( packet, flow_info, packet_type );

            //if( packet->payload_len > 0 )
            //    return ProcessPacketT6( packet, flow_info, packet_type );
            //else
            //    return ProcessPacketT5( packet, flow_info, packet_type );
        }
    }

    static int ProcessPacketT4( const Packet* packet, FlowInfo* flow_info, PacketType packet_type )
    {
        TDLogDebug( flow_info->flow_id, 1, "ProcessPacketT4() start" );

        // this could be client -> server request which IMMEDIATELY FOLLOWS 3-way handshake
        // (so-called T4), which is what we care about. Or it could be something else.
        if ( packet_type == PT_DIR_CS                                        && // this packet is client -> server
            packet->payload_len > 0                                          && // this is request from C to S, so request should contain some payload
            !PacketInfo_IsEmpty(& flow_info->packets[2])                     && // 3-way handshake established
            ntohl(packet->tcph->th_seq) == flow_info->packets[2].seq_num     && // seq is equal to previous packet's (ACK from handshake)
            ntohl(packet->tcph->th_ack) >= flow_info->packets[2].ack_num)       // ack is at least equal or bigger (because S could send something to C before T4 packet)
        {
            //printf("ProcessPacketT4 - OK!\n");
            return FlowInfo_InitPacket( flow_info, 3, packet, PT_DIR_CS );
        }
        // if this is not it
        else
        {
            //printf("ProcessPacketT4 - Some other ACK+PSH - forwarding to T5/T6!\n");
            TDLogDebug( flow_info->flow_id, 2, "Some other ACK+PSH - forwarding to T5/T6" );

            if( packet->payload_len > 0 )
                return ProcessPacketT6( packet, flow_info, packet_type );
            else
                return ProcessPacketT5( packet, flow_info, packet_type );
        }
    }

    static int ProcessPacketT5( const Packet* packet, FlowInfo* flow_info, PacketType packet_type )
    {
        TDLogDebug( flow_info->flow_id, 1, "ProcessPacketT5() start" );

        if ( packet->payload_len > 0 )
        {
            printf("Packet T5 should have payload_len == 0 but it has > 0\n");
            return 0;
        }

        // if this is ACK to T4 (see ProcessPacketT4())
        if ( packet_type == PT_DIR_SC                                       && // this packet is: S -> C
            !PacketInfo_IsEmpty(& flow_info->packets[3])                    && // T4 has been sent
            ntohl(packet->tcph->th_ack) >= flow_info->packets[3].seq_num + flow_info->packets[3].payload_len && // ack number can be bigger or equal becaue C could send more packets in the meantime (as a request)
            ntohl(packet->tcph->th_seq) == flow_info->packets[3].ack_num    )  // seq number correspond to T4 (because it should be the first packet from S->C after T4)
        {
            //printf("ProcessPacketT5 - OK!\n");
            return FlowInfo_InitPacket( flow_info, 4, packet, PT_DIR_SC );
        }

        // if this is not it
        else
        {
            //printf("ProcessPacketT5 - Ignoring the packet!\n");
            TDLogDebug( flow_info->flow_id, 2, "ProcessPacketT5 Ignoring the packet" );
            return 0;
        }
    }

    static int ProcessPacketT6( const Packet* packet, FlowInfo* flow_info, PacketType packet_type )
    {
        TDLogDebug( flow_info->flow_id, 1, "ProcessPacketT6() start" );

        if ( packet->payload_len == 0 )
        {
            printf("Packet T6 should have payload_len > 0 but it has 0\n");
            return 0;
        }

        if (
            packet_type == PT_DIR_SC                                        && // this packet is server -> client
            !PacketInfo_IsEmpty(& flow_info->packets[3])                    && // T4 has been set
            ((
                !PacketInfo_IsEmpty(& flow_info->packets[4])                    && // T5 has been set
                ntohl(packet->tcph->th_seq) == flow_info->packets[4].seq_num    && // T5 is only 'ACK' packet so T6 will have the same seq number
                ntohl(packet->tcph->th_ack) >= flow_info->packets[4].ack_num       // in the meantime S could receive some other packets from C
                                                                                   // so ACK num can be equal or bigger
            )
            ||
            (
                PacketInfo_IsEmpty(& flow_info->packets[4]) && g_T6noT5mode     && // flow is going to expire but T5 has NOT been set
                ntohl(packet->tcph->th_seq) == flow_info->packets[3].ack_num    && // it should correspond to ack num from T4
                ntohl(packet->tcph->th_ack) >= flow_info->packets[3].seq_num + flow_info->packets[3].payload_len  // in the meantime S could receive some other packets from C
                                                                                   // so ACK num can be equal or bigger
            ))
        ){
            //printf("ProcessPacketT6 - OK!\n");
            int ret = FlowInfo_InitPacket( flow_info, 5, packet, PT_DIR_SC );

            // if we were running is T6noT5 special mode
            if( g_T6noT5mode )
            {
                //assert( ret != TD_RET_DUPLICATE_PACKET );   // can't envision how that could happen, but maybe it could?

                if( ret == TD_RET_OK )
                {
                    return ret;
                }
                else
                {
                    return 0;
                }
            }

            // if we were running in normal mode
            else
            {
                if( ret == TD_RET_OK ) //|| ret == TD_RET_DUPLICATE_PACKET )   // TODO currently both are possible, need a decision on behaviour regarding TD_RET_DUPLICATE_PACKET
                {
                    TDLogDebug( flow_info->flow_id, 1, "ProcessPacketT6 -> CalculateAndLogResults" );
                    //printf("ProcessPacketT6 -> CalculateAndLogResults\n");
                    CalculateAndLogResults( flow_info );
                    return ret;
                }
                else
                {
                    //printf("ProcessPacketT6 - not sure...!\n");
                    return 0;   //TODO not sure if this branch makes sense.  It will be executed only on redundant but different packet.  Can this even happen, since on the first T6 we will erase the flow?  No other ProcessPacketT*() have this if either.
                }
            }
        }

        // if this is not it
        else if( !g_T6noT5mode )    // if, so we don't spam log again during flow expiration
        {
            //printf("T6 Ignoring the packet!\n");
            TDLogDebug( flow_info->flow_id, 2, "Ignoring the packet" );
        }
        return 0;
    }

    static int ProcessPacketRS( const Packet* packet, FlowInfo* flow_info, PacketType packet_type )
    {
        TDLogInfo( flow_info->flow_id, 1, "ProcessPacketRS() start" );

        // RST can come from either direction and at different times.  Thus we need to distinguish 
        // between RST in response to SYN (connection refused) and other RSTs

        // if RST is a response to SYN
        if( ! PacketInfo_IsEmpty(& flow_info->packets[0])                    &&  // previous packet (#0) was received (SYN packet)
            packet_type == PT_DIR_SC                                         &&  // this packet is server -> client
            ntohl(packet->tcph->th_ack) == flow_info->packets[0].seq_num + 1 )   // ack number corresponds to SYN's seq number
        {
            // sanity checks
            if (flow_info->packets[0].packet_type != PT_DIR_CS || flow_info->packets[0].tcp_flags != TH_SYN)
            {
                printf("ProcessPacketRS - wrong Packet T1\n");
                return 0;
            }

            // output T2 and expire the flow
            TDLogDebug( flow_info->flow_id, 2, "MATH: T2=%lu.%lu reset=1", packet->ts.tv_sec, packet->ts.tv_usec );
            
            //KK
            //printf("ProcessPacketRS -init...\n");
            FlowInfo_InitPacket( flow_info, 1, packet, PT_DIR_SC );
            TDLogDebug( flow_info->flow_id, 1, "ProcessPacketRS -> ExpireFlow" );
            //printf("ProcessPacketRS -> ExpireFlow\n");
            CalculateAndLogResults(flow_info);

            return 1;
        }

        // if RST is NOT a response to SYN
        else
        {
            // log it and expire the flow
            TDLogDebug( flow_info->flow_id, 2, "Unhandled RST received (no RS calculation preformed)" );
            return 0;
        }
    }

    static int ProcessPacket( FlowInfo* flow_info, const Packet* packet, PacketType packet_direction )
    {
        // get TCP flags
        uint8_t tcp_flags = packet->tcph->th_flags;

        // verify that flow_id is still valid: (verify packet's endpoints)
        switch( packet_direction )
        {
            // packet is unrelated to current flow we have in hashtable, yet the flow id is the same!
            case PT_UNRELATED:
                //printf("PT_UNRELATED!\n");
                return 0;
            break;

            // packet is server -> client
            case PT_DIR_SC:
                if( tcp_flags == TH_SYN+TH_ACK )
                {
                    return ProcessPacketT2( packet, flow_info );
                }
		//else
		//{
                //    if( packet->payload_len > 0 )
	        //        return ProcessPacketT6( packet, flow_info, packet_type );
                //    else
                //        return ProcessPacketT5( packet, flow_info, packet_type );
		//}

            /* yes, no break */

            // packet is client -> server
            case PT_DIR_CS:

                if( tcp_flags == TH_ACK )
                {
                    return ProcessPacketT3( packet, flow_info, packet_direction );  // may also call ProcessPacketT4()
                }
                else if( tcp_flags == TH_ACK+TH_PUSH || tcp_flags == TH_ACK+TH_PUSH+TH_FIN )
                {
                    return ProcessPacketT4( packet, flow_info, packet_direction );  // may also call ProcessPacketT5/T6()
                }
                else if( tcp_flags & TH_RST )
                {
                    return ProcessPacketRS( packet, flow_info, packet_direction );
                }
                else
                {
		    //printf("Unhandled packet\n");
                    TDLogDebug( flow_info->flow_id, 2, "Unhandled packet" );
                    return 0;
                }
                break;

            case PT_NULL: printf("ProcessPacket - packet_direction: PT_NULL!!!\n"); break;
            default:      printf("ProcessPacket - dafault no action!!!\n"); break;
        }

        return 0;
    }

    static int ProcessOooPacket( FlowInfo* flow_info, OooPacket* ooo_packet )
    {
        // this shouldn't be called until SYN has been processed
        if (flow_info->processed_packets < 1)
        {
            printf("ProcessOooPacket - WARNING there is no SYN packet (T1) - packet should be rejected!\n");
            return 0;
        }

        // if direction wasn't set yet, set it (now that SYN has been processed, this information is available)
        if( ooo_packet->packet_type == PT_UNDETERMINED )
            ooo_packet->packet_type = FlowInfo_GetOooPacketDirection( flow_info, ooo_packet );

        // build fake packet (it's a Packet struct with most fields not filled out and its dynamic storage (TCPHdr and payload) isn't really dynamic)
        Packet packet;
        TCPHdr header;
        packet.tcph = &header;
        header.th_seq   = ooo_packet->th_seq;
        header.th_ack   = ooo_packet->th_ack;
        header.th_flags = ooo_packet->th_flags;
        packet.ts          = ooo_packet->ts;
        packet.payload_len = ooo_packet->payload_len;

        // now process the fake packet
        return ProcessPacket( flow_info, &packet, ooo_packet->packet_type );
    }

////////////////////////////////////////////////////////////////////////////////
//
// SURICATA ENTRY POINT FUNCTION - PacketHandler
//
////////////////////////////////////////////////////////////////////////////////

    static int PacketHandler_AddOooPacket( FlowInfo* flow_info, const Packet* packet )
    {
        TDLogDebug( flow_info->flow_id, 1, "[ooo] Received ooo packet, queueing in ooo packet array as packet number %lu", flow_info->ooo_packets_cnt + 1 );

        int res = FlowInfo_AddOooPacket( flow_info, packet );
        if( res == TD_RET_ERR )
        {
            TDLogWarning( flow_info->flow_id, 2, "[ooo] Received too many ooo packets for this flow.  Giving up (expiring this flow)" );

            TDLogDebug( flow_info->flow_id, 1, "PacketHandler_AddOooPacket -> CalculateAndLogResults" );            
            // see if there's a T6 packet stuck in ooo array due to no T5 and process it (T5 is optional)
            int recovered_T6 = ProcessT6inOooDueToNoT5ifFound( flow_info );
            // log T data we're after (whatever data we collected up until this point

            //printf("PacketHandler_AddOooPacket -> CalculateAndLogResults\n");
            CalculateAndLogResults( flow_info );

            if( recovered_T6 == TD_RET_FLAG_USED_T6_WITHOUT_T5 )
            {
                return TD_RET_OK | TD_RET_FLAG_USED_T6_WITHOUT_T5;  // special case: we had T6 trapped in ooo because we were waiting for T5.  All done and taken care of now (we pulled the T6 out of ooo and applied it)
            }
            else
            {
                return TD_RET_ERR | TD_RET_FLAG_OOO_ADDED;          // the usual case: ooo array overflow
            }
        }
        else
        {
            return TD_RET_OK | TD_RET_FLAG_OOO_ADDED;
        }
    }

    static int PacketHandler_CreateNewFlow( const Packet* packet, FlowId flow_id, size_t ooo_packets_cnt, OooPacket ooo_packets[FLOWINFO_NUM_OF_OOOPACKETS] )
    {
        // The only out-of-order packet that can half-initialise the flow is a SYN+ACK.
        // This restriction is imposed because of the difficulty in determining whether an OOO packet
        // is a genuine packet of a new flow, or a continuation of old flow after we got our T1-T6
        // measurements done and deleted it to free up memory.

        // get TCP flags
        //assert( packet->tcph );
        uint8_t tcp_flags = packet->tcph->th_flags;
        FlowInfo* flow_info = &packet->flow->flowInfo;        

        if( tcp_flags == TH_SYN )
        {
            // (fully-initialise flow): create flow with SYN packet, aka packet T1
            TDLogDebug( flow_info->flow_id, 1, "[T1] Creating a new flow with SYN packet" );
            FlowInfo_CtorSynWithOooPackets( flow_info, flow_id, packet, ooo_packets_cnt, ooo_packets );

            return TD_RET_OK | ( ooo_packets_cnt ? TD_RET_FLAG_OOO_ADDED : 0 );
        }
        else if( tcp_flags == TH_SYN+TH_ACK )   // half-initialisation only allowed for SYN+ACK packets
        {
            if (ooo_packets_cnt > 0) // this should be non-zero only on SYN packets (when we're restarting the flow after it has been detected to be stale)
            {
                printf("PacketHandler_CreateNewFlow - TH_SYN+TH_ACK - ooo_packets_cnt > 0\n");
                return 0;
            }

            // (half-initialise flow): create flow and add packet to OOO packets.  Flow will only be paritally-initialised - FlowInfo_OnSynPacket() will have to be called to finish initialisation, when we finally receive the SYN packet
            TDLogDebug( flow_info->flow_id, 1, "[ooo T2] Creating a new flow with ooo SYN+ACK packet" );
            FlowInfo_CtorOoo( flow_info, flow_id, packet );

            return TD_RET_OK;
        }
        else
        {
            if (ooo_packets_cnt > 0) // this should be non-zero only on SYN packets (when we're restarting the flow after it has been detected to be stale)
            {
                printf("PacketHandler_CreateNewFlow - TH_SYN+TH_ACK - ooo_packets_cnt > 0\n");
                return 0;
            }

            // ingore all other OOO packets (note that this could simply be an old flow, after we processed T1-T6 and deleted the flow, thus we don't "remember" this flow
            TDLogDebug( flow_info->flow_id, 1, "Flow already established or there was not syn packet yet - ignoring" );

            return TD_RET_IGNORED;
        }
    }

    static int PacketHandler_OnSynPacket( const Packet* packet, FlowInfo* flow_info )
    {
        // if we're here, it means two things: 1. we just got a SYN packet, and 2. we ASSUME the flow was already (partially) initialised prior to receiving this SYN packet (see the if() block above).
        // So under normal circumstances if we're getting a SYN now, it means we didn't get it before and so now it's time to complete the flow initialisation.
        TDLogDebug( flow_info->flow_id, 1, "[ooo T1] Processing ooo SYN packet" );

        // so let's finish that flow initialisation
        int res = FlowInfo_OnSynPacket( flow_info, packet );

        // unexpected cases: when it turns out our assumption was wrong: the flow was already fully intialised (rather than partially).  In other words, we already received a SYN packet in the past (which initialised the flow fully), and now we're receiving another one!
        if( res == TD_RET_ERR )      // suprise, we already received a SYN packet before!  What's worse, this one is not a duplicate!!!
        {
            TDLogWarning( flow_info->flow_id, 2, "Received another, different SYN packet.  Assuming current flow is stale, and starting a new flow with this packet" );
            return 1;       // tell PacketHandler() to go again (by return-calling itself)
        }
        else if( res == TD_RET_DUPLICATE_PACKET ) // suprise, we already received a SYN packet before!  But since this one is identical, I guess we can let it slide
        {
            TDLogInfo( flow_info->flow_id, 2, "Received a duplicate SYN packet.  Ignoring" );
        }

        // the flow is okay, carry on normally
        return 0;
    }

    static int PacketHandler_ProcessOooPackets( FlowInfo* flow_info )
    {        
        // try to process ooo packets (and as long as we're making progress, keep looping)
        int processed_cnt = 0;
        int progressed;
        do
        {
            progressed = 0;

            //ooo_packets_cnt acts as a guard against segfaults, it is > 0 iff this array has been allocated
            for( size_t i=0; i<flow_info->ooo_packets_cnt; i++ )
            {
                if( !g_T6noT5mode )     // be quiet in T6noT5 mode
                {
                    TDLogDebug( flow_info->flow_id, 1, "Trying to process ooo packet %lu of %lu", i+1, flow_info->ooo_packets_cnt );
                }

                // if packet slot is empty, just log
                if( OooPacket_IsEmpty(&flow_info->ooo_packets[i]) )
                {
                    if( !g_T6noT5mode )     // be quiet in T6noT5 mode
                    {
                        TDLogDebug( flow_info->flow_id, 2, "Packet slot is empty" );
                    }
                }
                // else try to apply the packet
                else if( ProcessOooPacket(flow_info, &flow_info->ooo_packets[i]) )
                {
                    processed_cnt++;

                    // if packet succeeded, it could have expired the flow (for example, T6 and RS might do that)
                    if( g_T6noT5mode )
                    {
                        TDLogDebug( flow_info->flow_id, 2, "Successfully processed ooo packet %lu, flow is now expired", i+1 );
                        return processed_cnt;
                    }

                    // NOTE: we don't actually bother removing the empty-again processed packets and decrementing ooo_packets_cnt and/or moving remaining packets over, we just mark the processed ones empty and keep going.
                    //       This causes the packet slots to be non-reusable, but allows our code to be fast and simple.  The amount of packet slots allocated is pretty generous, so it should be plenty for all reasonable processing needs despite this "wasteful" behaviour
                    TDLogDebug( flow_info->flow_id, 2, "Successfully processed ooo packet %lu, marking it deleted in the array", i+1 );
                    OooPacket_Clear( &flow_info->ooo_packets[i] );                      // \_ and if succeeded, remove it from ooo packets
                    progressed = 1;                                                     // /                    and flag progress
                }
                else
                {
                    TDLogDebug( flow_info->flow_id, 2, "Processing ooo packet didn't succeed" );
                }
            }

        } while( progressed );

        return processed_cnt;
    }


    // --[ packet processing entry point ]------------------------------------------
    int PacketHandler( const Packet* packet, FlowId flow_id, size_t ooo_packets_cnt, OooPacket ooo_packets[FLOWINFO_NUM_OF_OOOPACKETS] )
    {
    /* FLOW DIAGRAM {{{

                                +------------------+
                                |   ignore packet  |
                                +------------------+
                                          ^
                                        N |
        +--------------+        +------------------+  Y      +------------------+
        | new packet   |        | packet==SYN+ACK? +-------->| half-initialise  +-----------------+
        +------+-------+        +------------------+         | flow             |                 |
               |                          ^                  +------------------+                 |
               v                        N |                                                       |
        +------+-------+  N     +---------+--------+  Y      +------------------+                 |
        | flow exists? +-------->   packet==SYN?   +-------->| fully-initialise |                 |
        +------+-------+        +------------------+         | flow             |                 |
             Y |                                             +------------------+                 |
               |                                                  ^                               |
               |                          .-----------------------'                               |
               v                        N |                                                       v
        +------+-------+  Y     +---------+--------+  Y      +------------------+         +--------------+
        | packet==SYN? +------->| full-init flow?  +-------->|  SYN is a dupe?  +         | queue packet |
        +------+-------+        +------------------+         +-----+--+---------+         | in OOO array |
             N |                                                 Y |  | N                 +--------------+
               |                          .------------------------'  |                        ^  ^  ^
               |                          |                           |                        |  |  |
               |                          v                           v                        |  |  |
               |                +------------------+         +------------------+              |  |  |
               |                |   ignore packet  |         |   restart flow   |              |  |  |
               |                +------------------+         +------------------+              |  |  |
               |                                                      |                        |  |  |
               |                                                      v                        |  |  |
               |                                             +------------------+              |  |  |
               |                                             |   salvaged ooo   |              |  |  |
               |                                             |     packets?     |              |  |  |
               |                                             +------------------+              |  |  |
               v                                                    Y |                        |  |  |
        +------+-------+  N                                           |                        |  |  |
        | full-init'ed |----------------------------------------------|------------------------+  |  |
        | flow?        |                                              |                           |  |
        +------+-------+                                              |                           |  |
             Y |                                                      |                           |  |
               v                                                      |                           |  |
        +------+-------+  N                                           |                           |  |
        | packet is    |----------------------------------------------|---------------------------+  |
        | related?     |                                              |                              |
        +------+-------+                                              |                              |
             Y |                                                      |                              |
               v                                                      |                              |
        +------+-------+  N                                           |                              |
        | packet       |----------------------------------------------|------------------------------+
        | process ok?  |                                              |
        +------+-------+                                              |
             Y |                                                      |
               v                                                      |
        +------+-------+                                              |
        | process OOO  |<---------------------------------------------'
        | array        |
        +--------------+                                                NICE TOOL: http://asciiflow.com




        NOTES:

        1. SYN packets are special
        They get special treatment, because they define flow's endpoints and without them, no other packet
        can be processed.  Notice that a SYN packet will never land in an OOO packet queue.

        2. Flow can have 3 states
            a. non-existant
                We don't have this flow in our flow table yet.  It will be created when the first packet of
                that flow appears, and initialised to one of the two below states.

            b. fully initialised
                We have the flow and received its SYN packet.  This is the usual case.

            c. half-initialised
                We have the flow, but haven't received its SYN packet yet (meaning, it was initialised with
                a different packet, which arrived out-of-order).  Until SYN comes in, we are unable to process
                other packets, thus any packet that arrives will automatically land in OOO packet queue.
                (at the time of writing, the only OOO packet that can half-initialise flow is a SYN+ACK.
                 This restriction is imposed because of the difficulty in determining whether an OOO packet
                 is a genuine packet of a new flow, or a continuation of old flow after we got our T1-T6
                 measurements done and deleted it to free up memory)

        3. OOO queue
        Out of order queue is a subcomponent of flow (once flow is deleted, so it its OOO queue).  Any packet
        that we cannot be processed right away lands in this queue.  Anytime afterwards, when an incoming packet
        is successfully processed, processing is retried for all the packets stored in the OOO queue.
        For memory safety, OOO queue has a size limit.  Once too many packets are placed in it, it will just
        remove the flow.

        4. Flow restart
        When we restart a flow, we must keep any OOO packets that are related to the new (restarted) flow.
        (imagine a case when SYN+ACK comes in first (placed in OOO), then corresponding SYN arrives.  If we
        didn't keep those packets, we would have lost the SYN+ACK packet)

        5. (Normal) Packet processing
        If we process all T1..T6 packets, we generate all the metrics we care about and we 

        6. OOO Packet processing
        Out-of-order packet processing is implemented in terms iterating through OOO array and calling
        the normal packet processing function on it.  Thus it works the same way underneath.

        7. Related packet
        Retalted packets are packets that have the same endpoints (source+destination ip+port numbers).
        Packets that have same endpoints, but with their direction reversed, are also considered related.

    }}} */
        //check flow, TCP header and flags
        if (packet->flow == NULL)
        {
            TDLogError( 0, 0, "Packet without a FLOW! Ignored!" );
            return TD_RET_IGNORED;
        }
        else
        //BELOW ONLY TCP packet with proper flags SHOULD PASS
        if (packet->tcph == NULL)
        {
            TDLogDebug( packet->flow->flowInfo.flow_id, 0, "Packet without a TCP header! Ignored!" );
            return TD_RET_IGNORED;
        }
        else
        if ( !packet->tcph->th_flags )
        {
            TDLogDebug( packet->flow->flowInfo.flow_id, 0, "Packet with flag 0!" );
            return TD_RET_IGNORED;
        }

        uint8_t tcp_flags = packet->tcph->th_flags;

        TDLogDebug( packet->flow->flowInfo.flow_id, 1, "tcp_flags: %x, src_port: %u, dst_port: %u, plen: %d, ts: %u, th_seq: %ld\n", tcp_flags, packet->sp, packet->dp, packet->payload_len, packet->ts.tv_usec, ntohl(packet->tcph->th_seq));
        //printf("ts: %u, tu: %u, tcp_flags: %x, src_port: %u, dst_port: %u, plen: %d, ts: %u, th_seq: %ld\n", packet->ts.tv_sec, packet->ts.tv_usec, tcp_flags, packet->sp, packet->dp, packet->payload_len, ntohl(packet->tcph->th_seq));

        // if we don't have this flow yet, must be new.  Let's try to create it (and return, since there'll be nothing else to process):
        //   on SYN     -> create and fully-initialise the flow,
        //   on SYN+ACK -> create and half-initialise the flow and place SYN+ACK packet in OOO array (queue),
        //   on other   -> do nothing, ignore the new flow.        
        if( packet->flow->flowInfo.flowInfoFree != ExpireFlow )
        {   
            int ret = PacketHandler_CreateNewFlow( packet, flow_id, ooo_packets_cnt, ooo_packets );

            // process ooo packets if there were any, otherwise just exit
            if( ret == (TD_RET_OK|TD_RET_FLAG_OOO_ADDED) )
            {
                int processed_cnt = PacketHandler_ProcessOooPackets( &packet->flow->flowInfo );   // if adding current packet succeeded above, there's a chance that now something in the ooo packet array might also process successfully.  So try processing anything (everything) outstanding in ooo packet array
                return TD_RET_OK | processed_cnt * TD_RET_CNT_OOO_PROCESSED;        // return OK and number of ooo processed
            }
            else
            {
                return ret;
            }
        } 

        // on SYN packet, finish flow initialisation if flow was previously half-initialised (this is the typical case).
        // In cases when the flow was already fully-initialised: do nothing if SYN is an exact duplicate of what we already had (weird to be receiving it again, but I've seen it happen), or restart the flow based on this SYN if indeed the SYN is different.
        if( tcp_flags == TH_SYN )
        {
            int flow_was_stale = PacketHandler_OnSynPacket( packet, &packet->flow->flowInfo );

            // if SYN was not a duplicate packet, expire old flow and create a flow with this SYN
            if( flow_was_stale )
            {
                // save ooo packets related to the new flow
                OooPacket new_ooo_packets[FLOWINFO_NUM_OF_OOOPACKETS];
                size_t new_ooo_packets_cnt = FlowInfo_CopyOooPacketsRelatedToNewFlow( &packet->flow->flowInfo, new_ooo_packets, packet );

                //restart the flow
                TDLogDebug( packet->flow->flowInfo.flow_id, 1, "flow_was_stale -> ExpireFlow !!!" );
                ExpireFlow( &packet->flow->flowInfo );
                return TD_RET_FLAG_FLOW_RESTARTED | PacketHandler( packet, flow_id, new_ooo_packets_cnt, new_ooo_packets );    // we scrapped the old flow and want to start a new flow with this packet -> go again (recursive call)
            }
            else
            {
                int processed_cnt = PacketHandler_ProcessOooPackets( &packet->flow->flowInfo );   // if adding current packet succeeded above, there's a chance that now something in the ooo packet array might also process successfully.  So try processing anything (everything) outstanding in ooo packet array
                return TD_RET_OK | processed_cnt * TD_RET_CNT_OOO_PROCESSED;        // return OK and number of ooo processed
            }
        }

        // if we haven't received SYN yet, there's nothing we can do except to add the incoming packet to OOO packet array and keep waiting for SYN
        if( packet->flow->flowInfo.processed_packets == 0 )
        {
            return PacketHandler_AddOooPacket( &packet->flow->flowInfo, packet );
        }

        // if we made it here, flow has already been initialised 
        // assert( packet->flow->flowInfo.processed_packets > 0 );

        // try processing the current packet.  If it fails, add it to ooo packets array and return, since any further processing will also not progress
        PacketType packet_direction = FlowInfo_GetPacketDirection( &packet->flow->flowInfo, packet );

        int res = ProcessPacket( &packet->flow->flowInfo, packet, packet_direction );
        
        if( res == 0 )
            return PacketHandler_AddOooPacket( &packet->flow->flowInfo, packet );

        // if adding current packet succeeded above, there's a chance that now something in the ooo packet array
        // might also process successfully.  So try processing anything (everything) outstanding in ooo packet array
        int processed_cnt = PacketHandler_ProcessOooPackets( &packet->flow->flowInfo );

        // return OK and number of ooo processed
        return res | processed_cnt * TD_RET_CNT_OOO_PROCESSED;
    }

////////////////////////////////////////////////////////////////////////////////
//
// RESULTS OUTPUT
//
////////////////////////////////////////////////////////////////////////////////
    

static int CalculateAndLogResults(FlowInfo* flow_info )
{
    static METRIC_ID td_metric_id = 0;

    //LOCAL THREAD VARAIBLES DECLARATIONS
    static __thread NanomsgHandler nn_handler_td;
    static __thread char nn_init_td = 0;

    TDLogDebug( flow_info->flow_id, 1, "CalculateAndLogResults" );

    if (td_metric_id < 1)
        td_metric_id = register_metric(RAW_DELAYS, (const char*)"suricata_collector");

    //check if data has already been logged or not initialized yet...
    if (flow_info->log_state == 1 || flow_info->flowInfoFree != ExpireFlow) //flow_info->flow_id != 1
        return 0;

    TimedeltaResult* r = NULL;

    // T1 (SYN)
    const PacketInfo* packet = & flow_info->packets[0];
    if( !PacketInfo_IsEmpty(packet) )
    {
        if( nn_init_td == 0 )
        {
            nn_init_td = 1;
            NanomsgInit(&nn_handler_td, nanomsg_url_td, BUF_SIZE_TD);
        }

        assert( packet->tcp_flags == TH_SYN );
        r = (TimedeltaResult*)NanomsgGetNextBufferElement(&nn_handler_td, sizeof(TimedeltaResult));
        SetIp_NET32_TO_HOST64(flow_info->ep.src_ip, r->src_ip);
        SetIp_NET32_TO_HOST64(flow_info->ep.dst_ip, r->dst_ip);
        r->src_port = flow_info->ep.src_port;
        r->dst_port = flow_info->ep.dst_port;
        r->seq_num = packet->seq_num;
        r->T1 = packet->timestamp;
        r->D2 = 0;
        r->D3 = 0;
        r->D4 = 0;
        r->D5 = 0;
        r->D6 = 0;
        r->reset = 0;
        r->complete = 0;
        r->flow_id = flow_info->flow_id;

        TDLogDebug(flow_info->flow_id, 2, "r->src_ip[0]: %llu", r->src_ip[0]);
        TDLogDebug(flow_info->flow_id, 2, "r->src_ip[1]: %llu", r->src_ip[1]);
        TDLogDebug(flow_info->flow_id, 2, "r->src_port: %u", r->src_port);
        TDLogDebug(flow_info->flow_id, 2, "r->dst_ip[0]: %llu", r->dst_ip[0]);
        TDLogDebug(flow_info->flow_id, 2, "r->dst_ip[1]: %llu", r->dst_ip[1]);
        TDLogDebug(flow_info->flow_id, 2, "r->dst_port: %u", r->dst_port);
        TDLogDebug(flow_info->flow_id, 2, "r->seq_num: %u", r->seq_num);
        TDLogDebug(flow_info->flow_id, 2, "r->T1: %u", r->T1);

        // printf("r->src_ip[0]: %llu\n", r->src_ip[0]);
        // printf("r->src_ip[1]: %llu\n", r->src_ip[1]);
        // printf("r->src_port: %u\n", r->src_port);
        // printf("r->dst_ip[0]: %llu\n", r->dst_ip[0]);
        // printf("r->dst_ip[1]: %llu\n", r->dst_ip[1]);
        // printf("r->dst_port: %u\n", r->dst_port);
        // printf("r->seq_num: %u\n", r->seq_num);
        // printf("r->T1: %lu\n", r->T1);
    }
    else
    {
        TDLogDebug( flow_info->flow_id, 2, "FIRST packet is EMPTY - log skipped");
        printf("FIRST packet is EMPTY - log skipped\n");
        return 0;
    }

    assert( r != NULL );
    flow_info->log_state = 1;

    // T2 (SYN+ACK), RS (RST)
    packet++;   // equivalent but maybe faster than packet = & flow_info->packets[1];
    if( !PacketInfo_IsEmpty(packet) )
    {
        if (packet->tcp_flags & TH_RST || packet->tcp_flags == TH_SYN+TH_ACK)
        {
            r->D2 = packet->timestamp - r->T1;
            TDLogDebug(flow_info->flow_id, 2, "r->D2: %u", r->D2);
            //printf("r->D2: %u\n", r->D2);

            if( packet->tcp_flags & TH_RST)
                r->reset = 1;
        }
        else
            printf("CalculateAndLogResults - Packet T2 unexpected flag: %x\n", packet->tcp_flags);
    }

    //T3 (ACK)
    packet++;
    if( !PacketInfo_IsEmpty(packet) )
    {
        if (packet->tcp_flags == TH_ACK)
        {
            r->D3 = packet->timestamp - r->T1;
            TDLogDebug(flow_info->flow_id, 2, "r->D3: %u", r->D3);
            //printf("r->D3: %u\n", r->D3);
        }
        else
            printf("CalculateAndLogResults - Packet T3 unexpected flag: %x\n", packet->tcp_flags);
    }

    // T4 (PSH+ACK ~FIN)
    packet++;
    if( !PacketInfo_IsEmpty(packet) )
    {
        if (packet->tcp_flags == TH_ACK || packet->tcp_flags == TH_PUSH+TH_ACK || packet->tcp_flags == TH_PUSH+TH_ACK+TH_FIN )
        {
            r->D4 = packet->timestamp - r->T1;
            TDLogDebug(flow_info->flow_id, 2, "r->D4: %u", r->D4);
            //printf("r->D4: %u\n", r->D4);
        }
        else
            printf("CalculateAndLogResults - Packet T4 unexpected flag: %x\n", packet->tcp_flags);
    }

    // T5
    //packet->tcp_flags == TH_ACK || packet->tcp_flags == TH_PUSH+TH_ACK || packet->tcp_flags == TH_PUSH+TH_ACK+TH_FIN
    //payload == 0
    packet++;
    if( !PacketInfo_IsEmpty(packet) )
    {
        if (packet->tcp_flags & TH_ACK)
        {
            r->D5 = packet->timestamp - r->T1;
            TDLogDebug(flow_info->flow_id, 2, "r->D5: %u", r->D5);
            //printf("r->D5: %u\n", r->D5);
        }
        else
            printf("CalculateAndLogResults - Packet T5 unexpected flag: %x\n", packet->tcp_flags);
    }

    // T6
    //packet->tcp_flags == TH_ACK || packet->tcp_flags == TH_PUSH+TH_ACK || packet->tcp_flags == TH_PUSH+TH_ACK+TH_FIN
    //payload > 0
    packet++;
    if( !PacketInfo_IsEmpty(packet) )
    {
        if( packet->tcp_flags & TH_ACK )
        {
            r->D6 = packet->timestamp - r->T1;
            r->complete = (r->D5 != 0);

            TDLogDebug(flow_info->flow_id, 2, "r->D6: %u", r->D6);
            //printf("r->D6: %u\n", r->D6);
        }
        else
            printf("CalculateAndLogResults - Packet T6 unexpected flag: %x\n", packet->tcp_flags);
    }

    //printf("r->reset: %u\n", (int)r->reset);
    //printf("r->complete: %u\n", (int)r->complete);

    //return LogResultsToUnified2( &r );

    NanomsgSendBufferIfNeeded(&nn_handler_td);
    update_metric(td_metric_id, 1);

    return 1;
}
