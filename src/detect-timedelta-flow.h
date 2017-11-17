#pragma once

#include "detect-timedelta-objects.h"
#include "detect-timedelta-common.h"
#include "detect-timedelta-logger.h"
#include "detect-timedelta-utils.h"


////////////////////////////////////////////////////////////////////////////////
//
// This file requires some explanation.  As you can see, it's all just a header
// file and there's no corresponding .c file.  If you deem it feasible, I guess
// you can refactor it into .h/.c pair.
//
// This file essentially contains the core data structures and the functions
// that operate on them.
//
// If you're a C++ programmer, you'll be right at home with what I've done here.
// If you don't know OOP, you might not like what's going on here.  Essentially,
// I tried to somewhat implement the mechanisms of OOP in C.  You can think of
// every struct here as a class, and all the indented functions that follow as
// its methods.  *_Ctor and *_Dtor are analogous of constructors/destructors, but
// the caller is resposible for the memory management.
//
// TODO:
// Nowever be warned, the "classes" are not fully encapsulated: the members
// are still sometimes accessed directly by other calling code.  I apologise for
// this, I haven't had the time to refactor it completely and eliminate this
// inconsistency (2015.03.26)
//
////////////////////////////////////////////////////////////////////////////////

#define CMP_ENDPOINTS(e1, e2) \
    (((e1)->src_ip[0] == (e2)->src_ip[0] && \
      (e1)->src_ip[1] == (e2)->src_ip[1] && \
      (e1)->src_ip[2] == (e2)->src_ip[2] && \
      (e1)->src_ip[3] == (e2)->src_ip[3] && \
      (e1)->dst_ip[0] == (e2)->dst_ip[0] && \
      (e1)->dst_ip[1] == (e2)->dst_ip[1] && \
      (e1)->dst_ip[2] == (e2)->dst_ip[2] && \
      (e1)->dst_ip[3] == (e2)->dst_ip[3] && \
      (e1)->src_port  == (e2)->src_port  && \
      (e1)->dst_port  == (e2)->dst_port))

#define CMP_ENDPOINTS_IS_REVERSED(e1, e2) \
    (((e1)->src_ip[0] == (e2)->dst_ip[0] && \
      (e1)->src_ip[1] == (e2)->dst_ip[1] && \
      (e1)->src_ip[2] == (e2)->dst_ip[2] && \
      (e1)->src_ip[3] == (e2)->dst_ip[3] && \
      (e1)->dst_ip[0] == (e2)->src_ip[0] && \
      (e1)->dst_ip[1] == (e2)->src_ip[1] && \
      (e1)->dst_ip[2] == (e2)->src_ip[2] && \
      (e1)->dst_ip[3] == (e2)->src_ip[3] && \
      (e1)->src_port  == (e2)->dst_port  && \
      (e1)->dst_port  == (e2)->src_port))

#define CMP_ENDPOINTS_AND_PACKET(e, p) \
    (((e)->src_ip[0] == GET_IPV4_SRC_ADDR_PTR(p)[0] && \
      (e)->src_ip[1] == GET_IPV4_SRC_ADDR_PTR(p)[1] && \
      (e)->src_ip[2] == GET_IPV4_SRC_ADDR_PTR(p)[2] && \
      (e)->src_ip[3] == GET_IPV4_SRC_ADDR_PTR(p)[3] && \
      (e)->dst_ip[0] == GET_IPV4_DST_ADDR_PTR(p)[0] && \
      (e)->dst_ip[1] == GET_IPV4_DST_ADDR_PTR(p)[1] && \
      (e)->dst_ip[2] == GET_IPV4_DST_ADDR_PTR(p)[2] && \
      (e)->dst_ip[3] == GET_IPV4_DST_ADDR_PTR(p)[3] && \
      (e)->src_port  == p->sp                       && \
      (e)->dst_port  == p->dp                       ))

#define CMP_ENDPOINTS_AND_PACKET_IS_REVERSED(e, p) \
    (((e)->src_ip[0] == GET_IPV4_DST_ADDR_PTR(p)[0] && \
      (e)->src_ip[1] == GET_IPV4_DST_ADDR_PTR(p)[1] && \
      (e)->src_ip[2] == GET_IPV4_DST_ADDR_PTR(p)[2] && \
      (e)->src_ip[3] == GET_IPV4_DST_ADDR_PTR(p)[3] && \
      (e)->dst_ip[0] == GET_IPV4_SRC_ADDR_PTR(p)[0] && \
      (e)->dst_ip[1] == GET_IPV4_SRC_ADDR_PTR(p)[1] && \
      (e)->dst_ip[2] == GET_IPV4_SRC_ADDR_PTR(p)[2] && \
      (e)->dst_ip[3] == GET_IPV4_SRC_ADDR_PTR(p)[3] && \
      (e)->src_port  == p->dp                       && \
      (e)->dst_port  == p->sp                       ))

    static inline void SetEndpoints(Endpoints* ep, const Packet* packet)
    {
        memcpy( ep->src_ip, GET_IPV4_SRC_ADDR_PTR(packet), sizeof(ep->src_ip) );
        memcpy( ep->dst_ip, GET_IPV4_DST_ADDR_PTR(packet), sizeof(ep->dst_ip) );
        ep->src_port = packet->sp;
        ep->dst_port = packet->dp;
    }

////////////////////////////////////////////////////////////////////////////////
//
// FLOWINFO STRUCTURES
//
////////////////////////////////////////////////////////////////////////////////

    int ExpireFlow( FlowInfo* flow_info );

    // some forward declarations
    static inline void PacketInfo_Clear  (      PacketInfo*);
    static inline int  PacketInfo_IsEmpty(const PacketInfo*);

    static inline void PacketInfo_CtorDef( PacketInfo* this )
    {
        PacketInfo_Clear( this );
    }

    static inline void PacketInfo_Ctor( PacketInfo* this, PacketType packet_type, const Packet* packet )
    {
        this->packet_type = packet_type;

        this->tcp_flags   = packet->tcph->th_flags;
        this->timestamp   = GetTimestampInMicroSec( packet->ts );
        this->seq_num     = ntohl( packet->tcph->th_seq );
        this->ack_num     = ntohl( packet->tcph->th_ack );
        this->payload_len = packet->payload_len;
    }

    static inline void PacketInfo_Dtor( PacketInfo* this )
    {
        if( !this || PacketInfo_IsEmpty(this) )
            return;

        PacketInfo_Clear( this );
    }

    static inline int PacketInfo_IsEmpty( const PacketInfo* this )
    {
        return( this->packet_type == PT_NULL );
    }

    static inline void PacketInfo_Clear( PacketInfo* this )
    {
        this->packet_type = PT_NULL;

        #if 1   // if you need to optimise, these shouldn't really need to be zero'd.  packet_type flags whether the packet is empty or not
         this->tcp_flags   = 0;
         this->seq_num     = 0;
         this->ack_num     = 0;
         this->payload_len = 0;
         this->timestamp   = 0;
        #endif
    }

    static int PacketInfo_Compare( const PacketInfo* this, PacketType packet_type, const Packet* packet )
    {
        return (
            this->packet_type == packet_type                        &&

            this->tcp_flags   == packet->tcph->th_flags             &&
            //this->timestamp   == packet->ts                       &&  // duplicate packets may have different timestamps, so checking this would make no sense
            this->seq_num     == ntohl( packet->tcph->th_seq )      &&
            this->ack_num     == ntohl( packet->tcph->th_ack )      &&  // not sure if this one should be enforced
            this->payload_len == packet->payload_len
        );
    }

    static inline void OooPacket_Ctor( OooPacket* this, const Packet* packet )
    {
        // src and dst and ports
        SetEndpoints(&this->ep, packet);

        this->packet_type = PT_UNDETERMINED;

        // TCP header
        this->th_flags = packet->tcph->th_flags;
        this->th_seq   = packet->tcph->th_seq;
        this->th_ack   = packet->tcph->th_ack;

        // timestamp
        this->ts = packet->ts;

        // payload
        this->payload_len = packet->payload_len;
    }

    static inline int OooPacket_IsEmpty( const OooPacket* this )
    {
        return( this->packet_type == PT_NULL );
    }

    static inline void OooPacket_Clear( OooPacket* this )
    {
        this->packet_type = PT_NULL;

        #if 0   // if you need to optimise, these shouldn't really need to be zero'd.  PacketInfo (pi) determines whether the packet is empty or not
         this->src.port    = 0;
         this->dst.port    = 0;
         ... TODO remaining vars
        #endif
    }

    static inline void OooPacket_Dtor( OooPacket* this )
    {
        // if you need to optimise, you could probably forego calling this destructor (at the time of writing anyway),
        if( !this || OooPacket_IsEmpty(this) )
            return;

        OooPacket_Clear( this );
    }


    // some forward declarations
    static inline int FlowInfo_AddOooPacket (FlowInfo*, const Packet*   );
    static inline int FlowInfo_AddOooPacket2(FlowInfo*, const OooPacket*);
    static inline int FlowInfo_InitPacket(FlowInfo*, size_t, const Packet*, PacketType);
    static inline PacketType FlowInfo_GetPacketDirection( const FlowInfo*, const Packet*);
    static        int FlowInfo_InspectDuplicatePacket(const FlowInfo*, size_t, const Packet*, PacketType);

    static inline void FlowInfo_Dtor( FlowInfo* this )
    {
        //printf("FlowInfo_Dtor this->flow_id: %u\n", this->flow_id);

        if( !this || !this->flow_id)
            return;

        // destroy ooo packets, if we have any
        if( this->ooo_packets_cnt > 0 )
        {
            for( size_t i=0; i<this->ooo_packets_cnt; i++ )
                OooPacket_Dtor( & this->ooo_packets[i] );

            this->ooo_packets_cnt = 0;
            TDLogDebug( this->flow_id, 2, "Deleting ooo array" );
        }

        // destroy packets
        for( size_t i=0; i<FLOWINFO_NUM_OF_PACKETS; i++ )
            PacketInfo_Dtor( &this->packets[i] );

        this->processed_packets = 0;

        this->flowInfoFree = NULL;

        //printf("FlowInfo_Dtor this->flow_id: %u END\n", this->flow_id);
        this->flow_id = (FlowId)0;

        this->log_state = 0;
    }

    static inline void FlowInfo_CtorSyn( FlowInfo* this, FlowId flow_id, const Packet* syn_packet )
    {
        // flow info
        this->log_state      = 0;
        this->flowInfoFree   = ExpireFlow;
        this->flow_id        = flow_id;//(FlowId)1;
        SetEndpoints(&this->ep, syn_packet);

        // OOO packets
        this->ooo_packets_cnt = 0;

        // construct the first packet
        PacketInfo_Ctor( & this->packets[0], PT_DIR_CS, syn_packet );
        this->processed_packets = 1;     // got T1 (SYN), now expecing T2 (SYN+ACK) to be next

        // construct remaining packets
        for( size_t i=1; i<FLOWINFO_NUM_OF_PACKETS; i++ )
            PacketInfo_CtorDef( & this->packets[i] );
    }

    static inline void FlowInfo_CtorSynWithOooPackets( FlowInfo* this, FlowId flow_id, const Packet* syn_packet, size_t ooo_packets_cnt, const OooPacket ooo_packets[FLOWINFO_NUM_OF_OOOPACKETS] )
    {
        FlowInfo_CtorSyn( this, flow_id, syn_packet );

        for( size_t i=0; i<ooo_packets_cnt; i++ )
            FlowInfo_AddOooPacket2( this, & ooo_packets[i] );
    }

    static inline void FlowInfo_CtorOoo( FlowInfo* this, FlowId flow_id, const Packet* first_packet )
    {
        // flow info
        this->log_state      = 0;
        this->flowInfoFree   = ExpireFlow;
        this->flow_id        = flow_id; //(FlowId)1;
        #if 1   // not really needed, could be thrown out during optimisation
        this->ep.src_ip[0]   = 0;
        this->ep.src_ip[1]   = 0;
        this->ep.src_ip[2]   = 0;
        this->ep.src_ip[3]   = 0;
        this->ep.dst_ip[0]   = 0;
        this->ep.dst_ip[1]   = 0;
        this->ep.dst_ip[2]   = 0;
        this->ep.dst_ip[3]   = 0;
        this->ep.src_port    = 0;
        this->ep.dst_port    = 0;
        #endif

        // OOO packets
        this->ooo_packets_cnt = 0;
        FlowInfo_AddOooPacket( this, first_packet );

        // construct all packets
        for( size_t i=0; i<FLOWINFO_NUM_OF_PACKETS; i++ )
            PacketInfo_CtorDef( & this->packets[i] );
        this->processed_packets = 0;     // still waiting for that T1 (SYN)
    }

    static inline int FlowInfo_OnSynPacket( FlowInfo* this, const Packet* syn_packet )
    {
        // if we never got a SYN before
        if( this->processed_packets == 0 )
        {
            // init endpoints
            SetEndpoints(&this->ep, syn_packet);

            // add SYN packet
            this->processed_packets = 1;     // got T1 (SYN), now expecing T2 (SYN+ACK) to be next
            return FlowInfo_InitPacket( this, 0, syn_packet, PT_DIR_CS );
        }

        // if we already have a SYN in our flow
        else
        {
            PacketType pt = FlowInfo_GetPacketDirection( this, syn_packet );    // establish if the new SYN packet has the same endpoints
            return FlowInfo_InitPacket( this, 0, syn_packet, pt );
        }
    }

    static inline int FlowInfo_AddOooPacket( FlowInfo* this, const Packet* packet )
    {
        // add the ooo packet
        if( this->ooo_packets_cnt < FLOWINFO_NUM_OF_OOOPACKETS )
        {
            OooPacket_Ctor( & this->ooo_packets[this->ooo_packets_cnt++], packet );
            return TD_RET_OK;
        }
        else
        {
            return TD_RET_ERR;
        }
    }

    static inline int FlowInfo_AddOooPacket2( FlowInfo* this, const OooPacket* ooo_packet )
    {
        // add the ooo packet
        if( this->ooo_packets_cnt < FLOWINFO_NUM_OF_OOOPACKETS )
        {
            this->ooo_packets[this->ooo_packets_cnt++] = *ooo_packet;
            return TD_RET_OK;
        }
        else
        {
            return TD_RET_ERR;
        }
    }

    static inline int FlowInfo_InitPacket( FlowInfo* this, size_t packet_idx, const Packet* packet, PacketType packet_type )
    {
        // normal case: add the packet
        if( PacketInfo_IsEmpty(& this->packets[packet_idx]) )
        {
            this->processed_packets = packet_idx + 1;
            PacketInfo_Ctor( & this->packets[packet_idx], packet_type, packet );
            return TD_RET_OK; //was 1;
        }

        // we've already have a packet of this type!
        else
        {
            // TODO/NOTE: you may want to optimise this:
            // At the time of writing (2015.03.22), we just take a look if it's a duplicate or not, but in either case, do nothing about it.
            // (we return the result, which just keeps getting forwarded upstream until it is ignored eventually.  HOWEVER, unit tests do use it,
            //  so if you decide to optimise it out for production, leave it for the unit tests)
            return FlowInfo_InspectDuplicatePacket( this, packet_idx, packet, packet_type );    // at the time of writing, resturns TD_RET_DUPLICATE_PACKET or TD_RET_ERR
        }
    }

    static inline PacketType FlowInfo_GetPacketDirection( const FlowInfo* this, const Packet* packet )
    {
        //if( PKT_IS_TOSERVER(packet) )
        if( CMP_ENDPOINTS_AND_PACKET(&this->ep, packet) )
        {
            return PT_DIR_CS;   // flow matches (packet dir is client -> server)
        }

        //if( PKT_IS_TOCLIENT(packet) )
        if( CMP_ENDPOINTS_AND_PACKET_IS_REVERSED(&this->ep, packet) )
        {
            return PT_DIR_SC;  // flow is reversed (packet dir is server -> client)
        }

        // flow is unrelated
        return PT_UNRELATED;
    }

    static inline PacketType FlowInfo_GetOooPacketDirection( const FlowInfo* this, const OooPacket* ooo_packet )
    {
        if( CMP_ENDPOINTS(&this->ep, &ooo_packet->ep) )
        {
            return PT_DIR_CS;   // flow matches (packet dir is client -> server)
        }

        if( CMP_ENDPOINTS_IS_REVERSED(&this->ep, &ooo_packet->ep) )
        {
            return PT_DIR_SC;  // flow is reversed (packet dir is server -> client)
        }

        // flow is unrelated
        return PT_UNRELATED;
    }

    static int FlowInfo_InspectDuplicatePacket( const FlowInfo* this, size_t packet_idx, const Packet* packet, PacketType packet_type )
    {
        // NOTE: At the time of writing (2015.03.22), the result of this function isn't really used for anything except unit tests.
        //       It is called only by FlowInfo_InitPacket(), which hands over the result, but that result gets eventually discarded.
        //       Except for the unit tests, that is.

        // it seems we already captured a packet of this type.
        // Check if it's identical (perhaps it's being retransmitted?)
        const PacketInfo* packet_old = & this->packets[packet_idx];
        PacketType packet_direction = FlowInfo_GetPacketDirection( this, packet );
        if( PacketInfo_Compare(packet_old, packet_direction, packet) )
        {
            // notify that the packet was retransmitted.  Note that in many cases retransmissions are normal, so our logic should not be affected by them.
            // Some examples of retransmissions: switch's SPAN port copying BOTH inbound and outbound traffic (in such case each packet will be seen twice)

            TDLogInfo( this->flow_id, 2, "Duplicate packet detected!" );
            
            return TD_RET_DUPLICATE_PACKET;
        }
        else
        {
            // TODO and now what?  Leave the old one or update with the new one, or maybe just scrap the flow altogether?

            TDLogWarning( this->flow_id, 2, "Redundant but different packet detected!" );

            return TD_RET_ERR;
        }
    }

    static inline int FlowInfo_CopyOooPacketsRelatedToNewFlow( const FlowInfo* this, OooPacket new_ooo_packets[FLOWINFO_NUM_OF_OOOPACKETS], const Packet* new_flow_packet )
    {
        //printf("CornerCase: CopyOooPacketsRelatedToNewFlow\n");
        size_t new_ooo_packets_cnt = 0;

        if( this->ooo_packets_cnt > 0 )
        {
            // create a skeleton flow struct, so we can easily compare src/dst endpoints
            FlowInfo fake_new_flow;
            SetEndpoints(&fake_new_flow.ep, new_flow_packet);

            // copy all ooo packets related to the new flow
            for( size_t i=0; i<this->ooo_packets_cnt; i++ )
            {
                PacketType pt = FlowInfo_GetOooPacketDirection( &fake_new_flow, & this->ooo_packets[i] );
                if( pt != PT_UNRELATED )
                {
                    TDLogDebug( this->flow_id, 2, "Salvaging ooo packet %lu of %lu", i+1, this->ooo_packets_cnt );
                    new_ooo_packets[new_ooo_packets_cnt++] = this->ooo_packets[i];
                }
            }
        }

        return new_ooo_packets_cnt;
    }
