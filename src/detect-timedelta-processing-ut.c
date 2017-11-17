#include "detect-timedelta-processing-ut.h"
#include "detect-timedelta-ut-utils.h"
#include "detect-timedelta-processing.h"

//unneseserry function
static FlowInfo* GetFlowInfoFromHT( FlowId flow_id )
{
    return NULL;
}

//unneseserry function
int ExpireOldFlows ( TimeInMicroSec now, FlowId flow_id )
{
    return 0;
}

static size_t CountNonemptyOooPackets( const FlowInfo* flow_info )
{
    size_t cnt = 0;

    for( size_t i=0; i<flow_info->ooo_packets_cnt; i++ )
        if( !OooPacket_IsEmpty(&flow_info->ooo_packets[i]) )
            cnt++;

    return cnt;
}

static int TestProcessing_NoTcpHeader()
{
    Packet packet;
    packet.tcph = NULL;
    int ret = PacketHandler( &packet, 12345, 0, NULL );
    int res = TestIntEq( "Should detect TCP header doesn't exist", TD_RET_IGNORED, ret );

    return res;
}

static int TestProcessing_FlowDoesNotExist()
{
    int res = 1;

    FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
    res &= TestIntEq( "No such FlowInfo yet", NULL, flow_info );

    return res;
}

static int TestProcessing_FirstPacketNotSynOrSynAck()
{
    int res = 1;

    // create a packet with all TCP flags clear
    Packet packet;
    UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, 0, "" );  // 0 = all TCP flags clear

    // expects a SYN packet, should therefore fail
    int ret = PacketHandler( &packet, 12345, 0, NULL );
    FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
    res &= TestIntEq( "Packet should be ignored",    TD_RET_IGNORED, ret );
    res &= TestIntEq( "FlowInfo should not exist",   NULL,     flow_info );

    return res;
}

static int TestProcessing_Helper_ConvolutedHandshake()
{
    int res = 1;

    {
        // create a SYN packet
        Packet packet1;
        UTH_FillPacket( &packet1, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

        // create a SYN+ACK packet
        Packet packet2;
        UTH_FillPacket( &packet2, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_SYN+TH_ACK, "" );

        // create an ACK packet
        Packet packet3;
        UTH_FillPacket( &packet3, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK, "" );

        // SYN+ACK - should create half-initialised flow
        int ret = PacketHandler( &packet2, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "SYN+ACK: should land in ooo",      1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",        NULL, flow_info );

        // ooo queue should now exist
        res &= TestIntNeq( "ooo queue(array) should now exist",        NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo queue(array) should contain 1 packet",     1, flow_info->ooo_packets_cnt );
        res &= TestIntEq( "So far no packets should have been processed", 0, flow_info->processed_packets );

        // SYN - should fully-initialise flow
        ret = PacketHandler( &packet1, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "SYN: should automatically process SYN+ACK", TD_RET_OK | 1*TD_RET_CNT_OOO_PROCESSED, ret );
        res &= TestIntNeq( "FlowInfo should exist",                    NULL, flow_info );

        // ooo queue should still exist, but SYN+ACK should be (marked as) deleted
        res &= TestIntNeq( "ooo should exist",            NULL,     flow_info->ooo_packets             );
        res &= TestIntEq( "ooo should contain no (active) packets", 0, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "SYN+ACK should have gotten automatically processed from ooo queue", 2, flow_info->processed_packets );

        // ACK - should process normally
        ret = PacketHandler( &packet3, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "ACK: should process normally",     1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",        NULL, flow_info );
    }

    return res;
}

static int TestProcessing_ConvolutedHandshake()
{
    int res = 1;

    res &= TestProcessing_Helper_ConvolutedHandshake();

    return res;
}

static int TestProcessing_MultipleSyn()
{
    int res = 1;

    // create a SYN packet
    Packet packet;
    UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );  // 0 = all TCP flags clear

    // expects a SYN packet - should pass
    int ret = PacketHandler( &packet, 12345, 0, NULL );
    FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
    res &= TestIntEq( "First SYN: should create full-flow", TD_RET_OK,        ret );
    res &= TestIntNeq( "FlowInfo should exist",             NULL,       flow_info );

    // send the same packet again - should get ignored with a warning
    ret = PacketHandler( &packet, 12345, 0, NULL );
    flow_info = GetFlowInfoFromHT( 12345 );         // when things go wrong, whole flow should be expired
    res &= TestIntEq( "Duplicate SYN: should get ignored",  TD_RET_OK,        ret );
    res &= TestIntNeq( "FlowInfo should exist",             NULL,       flow_info );

    // send the SYN again, but altered a little - the old flow should be destroyed and new one formed with it
    packet.src.address.address_un_data32[0] = 42;   // different src IP
    ret = PacketHandler( &packet, 12345, 0, NULL );
    flow_info = GetFlowInfoFromHT( 12345 );         // when PacketHandler() recurses, it passes the flow_id to itself (FlowInfo* get destroyed and reallocated)
    res &= TestIntEq( "Different SYN: should restart flow",            TD_RET_OK | TD_RET_FLAG_FLOW_RESTARTED, ret );
    res &= TestIntNeq( "FlowInfo should be destructed but recreated",  NULL,                             flow_info );

    return res;
}

static int TestProcessing_RestartFlowWithSalvagedOooPackets()
{
    int res = 1;

    // just another regular flow
    {
        // create a SYN packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );  // 0 = all TCP flags clear

        // expects a SYN packet - should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "1st SYN: should create full flow",       TD_RET_OK,        ret );
        res &= TestIntNeq( "FlowInfo should exist",                 NULL,       flow_info );

        // ooo queue should not exist at this stage
        res &= TestIntEq( "ooo queue(array) should not exist", NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo queue(array) should not exist",    0, flow_info->ooo_packets_cnt );
    }

    // send 2 unrelated flows
    {
        // unrelated flow1 - should be sucked in as ooo packets and processed after SYN is sent and flow is restared
        uint32_t TEST_IP_3 = 42;
        Packet packet1;
        UTH_FillPacket( &packet1,  TEST_IP_3, 3333, TEST_IP_2, 2222, 0, "" );  // 0 = all TCP flags clear
        Packet packet1r;
        UTH_FillPacket( &packet1r, TEST_IP_2, 2222, TEST_IP_3, 3333, TH_SYN+TH_ACK, "" );  // 0 = all TCP flags clear

        // unrelated flow2 - should be sucked in as ooo packets, but dropped when flow1 SYN is sent
        uint32_t TEST_IP_4 = 24;
        Packet packet2;
        UTH_FillPacket( &packet2, TEST_IP_4, 1111, TEST_IP_2, 2222, 0, "" );  // 0 = all TCP flags clear

        // send an unrelated regular packet (IP3 -> IP2) - should get added to ooo packet array
        packet1.tcph->th_flags = TH_ACK;                        // regular packet
        int ret = PacketHandler( &packet1, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "ACK IP3->IP2: should land in ooo queue", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL,       flow_info );

        // ooo queue should now exist
        res &= TestIntNeq( "ooo queue(array) should now exist",       NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo queue(array) should contain 1 packet",    1, flow_info->ooo_packets_cnt );

        // send another unrelated packet (IP3 -> IP2) - should get added to ooo packet array
        packet1.tcph->th_flags = TH_ACK;                        // regular packet
        ret = PacketHandler( &packet1, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "ACK IP3->IP2: should land in ooo queue", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                                  NULL,       flow_info );

        // send an unrelated packet (IP4 -> IP2) - should get added to ooo packet array
        packet2.tcph->th_flags = TH_ACK;                        // regular packet
        ret = PacketHandler( &packet2, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "ACK IP4->IP2: should land in ooo queue",   TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                                    NULL,       flow_info );

        // send another unrelated SYN+ACK (IP2 -> IP3) - should get added to ooo packet array
        packet1r.tcph->th_flags = TH_SYN+TH_ACK;                // SYN+ACK packet
        packet1r.tcph->th_ack = htonl( ntohl(packet1.tcph->th_seq) + 1 );
        ret = PacketHandler( &packet1r, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "SYN+ACK IP2->IP3: should land in ooo queue",   TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                                        NULL,       flow_info );

        // finally, send the SYN (IP3 -> IP2) - the flow should be restarted and suck process SYN+ACk packet as well
        packet1.tcph->th_flags = TH_SYN;                        // SYN packet
        ret = PacketHandler( &packet1, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );                 // when PacketHandler() recurses, it passes the flow_id to itself (FlowInfo* get destroyed and reallocated)
        res &= TestIntEq( "SYN IP3->IP2: should restart flow with IP3 packets in ooo array", TD_RET_OK | TD_RET_FLAG_FLOW_RESTARTED | (1*TD_RET_CNT_OOO_PROCESSED), ret );
        res &= TestIntNeq( "FlowInfo should be destructed but recreated",                    NULL, flow_info );

        // also, all TEST_IP_3 packets should be salvaged (copied to its ooo array), of which SYN+ACK should have gotten automatically processed
        res &= TestIntNeq( "ooo queue(array) should exist",            NULL, flow_info->ooo_packets             );
        res &= TestIntEq( "ooo queue(array) should contain 2 packets",    2, CountNonemptyOooPackets(flow_info) );  // 2, because SYN+ACK got processed, so it should no longer be there
        res &= TestIntEq( "SYN+ACK should have gotten automatically processed from ooo queue", 2, flow_info->processed_packets );
    }

    return res;
}

static int TestProcessing_SecondPacketSynAckWrongDirection()
{
    int res = 1;

    {
        // create a SYN packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "SYN: should succeed",                   1,       ret );
        res &= TestIntEq( "There should be 1 processed packet",    1, flow_info->processed_packets );
        res &= TestIntNeq( "FlowInfo should exist",             NULL, flow_info );

        // ooo queue should not exist at this stage
        res &= TestIntEq( "ooo queue should not exist", NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo queue should not exist",    0, flow_info->ooo_packets_cnt );
    }

    {
        // create a SYN+ACK packet, but wrong direction
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN+TH_ACK, "" );

        // should fail
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "SYN+ACK in wrong direction: should land in ooo", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntEq( "There should still be 1 processed packet",       1, flow_info->processed_packets );
        res &= TestIntNeq( "FlowInfo should exist",                      NULL, flow_info );

        // ooo queue should now exist
        res &= TestIntNeq( "ooo queue should now exist",       NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo queue should contain 1 packet",    1, flow_info->ooo_packets_cnt );
    }

    return res;
}

static int TestProcessing_SecondPacketSynAck()
{
    int res = 1;

    {
        // create a SYN packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
    }

    {
        // create a SYN+ACK packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_SYN+TH_ACK, "" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
    }

    return res;
}

static int TestProcessing_SecondPacketRst()
{
    int res = 1;

    for( int i=0; i<2; i++ )
    {
        {
            // create a SYN packet
            Packet packet;
            UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

            // should pass
            int ret = PacketHandler( &packet, 12345, 0, NULL );
            FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
            res &= TestIntEq( "Processing packet should succeed",    1,       ret );
            res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
        }

        {
            // create a RST packet
            Packet packet;
            UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_RST, "" );

            // should pass
            int ret = PacketHandler( &packet, 12345, 0, NULL );
            FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
            res &= TestIntEq( "Processing packet should succeed",    1,       ret );
            res &= TestIntEq( "FlowInfo should expire",           NULL, flow_info );
        }

        // reset should remove the FlowInfo from hash, thus another SYN - RST sequence
        // should run just like the first time
    }

    return res;
}

static int TestProcessing_AnyPacketRst()
{
    int res = 1;

    for( int i=0; i<2; i++ )
    {
        {
            // create a SYN packet
            Packet packet;
            UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

            // should pass
            int ret = PacketHandler( &packet, 12345, 0, NULL );
            FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
            res &= TestIntEq( "Processing SYN should succeed",    1 + i*TD_RET_FLAG_FLOW_RESTARTED, ret );  // second time around, there will be a flow restart
            res &= TestIntNeq( "FlowInfo should exist",        NULL, flow_info );
        }

        {
            // create a RST packet (note that its direction is the same as the SYN before it)
            Packet packet;
            UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_RST, "" );

            // should pass
            int ret = PacketHandler( &packet, 12345, 0, NULL );
            FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
            res &= TestIntEq( "RST in wrong direction: should land in ooo", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
            res &= TestIntNeq( "FlowInfo should exist",                     NULL, flow_info );
        }

        // reset should remove the FlowInfo from hash, thus another SYN - RST sequence
        // should run just like the first time
    }

    return res;
}

static int TestProcessing_Helper_FullHandshake( FlowId flow_id )
{
    int res = 1;

    {
        // create a SYN packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

        // should pass
        int ret = PacketHandler( &packet, flow_id, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( flow_id );
        res &= TestIntEq( "Processing packet should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
    }

    {
        // create a SYN+ACK packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_SYN+TH_ACK, "" );

        // should pass
        int ret = PacketHandler( &packet, flow_id, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( flow_id );
        res &= TestIntEq( "Processing packet should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
    }

    {
        // create an ACK packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK, "" );

        // should pass
        int ret = PacketHandler( &packet, flow_id, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( flow_id );
        res &= TestIntEq( "Processing packet should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
    }

    return res;
}

static int TestProcessing_FullHandshake()
{
    int res;

    res = TestProcessing_Helper_FullHandshake( 12345 );

    return res;
}

static int TestProcessing_FullHandshakeThenSyn()
{
    int res;

    res  = TestProcessing_Helper_FullHandshake( 12345 );

    {
        // create a SYN packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

        // should fail
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "2nd SYN: should restart flow",     TD_RET_OK | TD_RET_FLAG_FLOW_RESTARTED,       ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
    }

    return res;
}

static int TestProcessing_HappyPath1()
{
    int res = 1;

    res = TestProcessing_Helper_FullHandshake( 12345 );

    {
        // create a non-zero request packet (aka T4)
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK+TH_PUSH, "RQ" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T4) should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );
    }

    {
        // create an ACK packet (aka T5)
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T5) should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );
    }

    {
        // create response packet (aka T6)
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T6) should succeed",    1,       ret );
        res &= TestIntEq( "FlowInfo should be processed and removed", NULL, flow_info );
    }

    // now that the flow is expired, another handshake should go through no problem
    res &= TestProcessing_Helper_FullHandshake( 12345 );

    return res;
}

static int TestProcessing_HappyPathOoo1()
{
    int res = 1;

    res = TestProcessing_Helper_FullHandshake( 12345 );

    {
        // create a non-zero request packet (aka T4)
        Packet packet4;
        UTH_FillPacket( &packet4, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK+TH_PUSH, "RQ" );

        // create an ACK packet (aka T5)
        Packet packet5;
        UTH_FillPacket( &packet5, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "" );

        // create response packet (aka T6)
        Packet packet6;
        UTH_FillPacket( &packet6, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // ooo queue should not exist at this stage
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "ooo queue(array) should not exist", NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo queue(array) should not exist",    0, flow_info->ooo_packets_cnt );

    // now apply the packets in reverse order

        // send T6 - should land in ooo
        int ret = PacketHandler( &packet6, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T6) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        // ooo queue should now exist
        res &= TestIntNeq( "ooo queue(array) should now exist",        NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo queue(array) should contain 1 packet",    1, flow_info->ooo_packets_cnt );
        res &= TestIntEq( "So far 3 packets should have been processed", 3, flow_info->processed_packets );

        // send T5 - should land in ooo
        ret = PacketHandler( &packet5, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T5) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        // ooo queue should still exist
        res &= TestIntEq( "ooo queue(array) should contain 2 packets",   2, flow_info->ooo_packets_cnt );
        res &= TestIntEq( "No futher progess in packet processing",      3, flow_info->processed_packets );

        // send T4 - everything should now process
        ret = PacketHandler( &packet4, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T4) should succeed",    TD_RET_OK + 2*TD_RET_CNT_OOO_PROCESSED, ret );
        res &= TestIntEq( "FlowInfo should be processed and removed", NULL, flow_info );

        // flow should no longer exit
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "FlowInfo should no longer exist", NULL, flow_info );
    }

    // now that the flow is expired, another handshake should go through no problem
    res &= TestProcessing_Helper_FullHandshake( 12345 );

    return res;
}

static int TestProcessing_HappyPathOoo2()
{
    int res = 1;

    res = TestProcessing_Helper_ConvolutedHandshake();

    {
        // create a non-zero request packet (aka T4)
        Packet packet4;
        UTH_FillPacket( &packet4, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK+TH_PUSH, "RQ" );

        // create an ACK packet (aka T5)
        Packet packet5;
        UTH_FillPacket( &packet5, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "" );

        // create response packet (aka T6)
        Packet packet6;
        UTH_FillPacket( &packet6, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // ooo queue should exist because of what happened in TestProcessing_Helper_ConvolutedHandshake()
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "So far 3 packets should have been processed", 3, flow_info->processed_packets );
        res &= TestIntNeq( "ooo should exist", NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo should have just 1 (removed) element", 1, flow_info->ooo_packets_cnt );
        res &= TestIntEq( "ooo should contain 0 (active) packets",    0, CountNonemptyOooPackets(flow_info) );  // 2, because SYN+ACK got processed, so it should no longer be there

    // now apply the packets in reverse order

        // send T6 - should land in ooo
        int ret = PacketHandler( &packet6, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T6) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        // ooo queue should now exist
        res &= TestIntNeq( "ooo should now exist",                NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo should contain 1 (active) packet",    1, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "So far 3 packets should have been processed", 3, flow_info->processed_packets );

        // send T5 - should land in ooo
        ret = PacketHandler( &packet5, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T5) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        // ooo queue should still exist
        res &= TestIntEq( "ooo should contain 2 (active) packets",  2, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "No futher progess in packet processing", 3, flow_info->processed_packets );

        // send T4 - everything should now process
        ret = PacketHandler( &packet4, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T4) should succeed",    TD_RET_OK + 2*TD_RET_CNT_OOO_PROCESSED, ret );
        res &= TestIntEq( "FlowInfo should be processed and removed", NULL, flow_info );

        // flow should no longer exit
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "FlowInfo should no longer exist", NULL, flow_info );
    }

    // now that the flow is expired, another handshake should go through no problem
    res &= TestProcessing_Helper_FullHandshake( 12345 );

    return res;
}

static int TestProcessing_HappyPathOooT5()
{
    int res = 1;
    
    res = TestProcessing_Helper_FullHandshake( 12345 );

    // T4
    {
        // create a non-zero request packet (aka T4)
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK+TH_PUSH, "RQ" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T4) should succeed", TD_RET_OK,       ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL,      flow_info );
    }

    // T5 - create but don't send yet
    Packet packetT5;
    {
        // create an ACK packet (aka T5)
        UTH_FillPacket( &packetT5, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "" );
    }

    // T6
    {
        // create response packet (aka T6)
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // send T6 - should land in ooo queue, but since we're missing T5
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T6) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        res &= TestIntEq( "ooo should contain 1 (active) packet",    1, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "So far 4 packets should have been processed", 4, flow_info->processed_packets );
    }

    // T5 - send the missing ooo packet
    {
        // should pass
        int ret = PacketHandler( &packetT5, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packetT5 (T5) should succeed", TD_RET_OK + 1*TD_RET_CNT_OOO_PROCESSED, ret );
        res &= TestIntEq( "FlowInfo should be processed and removed", NULL, flow_info );
    }

    // now that the flow is expired, another handshake should go through no problem
    res &= TestProcessing_Helper_FullHandshake( 12345 );

    return res;
}

static int TestProcessing_HappyPathNoT5()
{
    int res = 1;
    
    res = TestProcessing_Helper_FullHandshake( 12345 );

    // T4
    {
        // create a non-zero request packet (aka T4)
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK+TH_PUSH, "RQ" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T4) should succeed", TD_RET_OK,       ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL,      flow_info );
    }

    // T5 - create but don't send (we won't be sending it)
    {
        // create an ACK packet (aka T5)
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "" );
    }

    // T6
    {
        // create response packet (aka T6)
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // send T6 - should land in ooo queue, but since we're missing T5
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T6) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        res &= TestIntEq( "ooo should contain 1 (active) packet",    1, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "So far 4 packets should have been processed", 4, flow_info->processed_packets );
    }

    // send a bunch of packets to fill up the ooo queue all the way to the max limit
    for( size_t i=1; i < FLOWINFO_NUM_OF_OOOPACKETS; i++ )
    {
        // create some packet that's not T1-T6
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Generic packet should land in ooo queue", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        res &= TestIntEq( "ooo should contain more (active) packets",    i+1, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "So far 3 packets should have been processed", 4,   flow_info->processed_packets );
    }

    // now send one more, the one that will overflow the ooo queue.
    // It should expire the flow, and everything should be processed fine, but in "missing T5 mode"
    {
        // create some packet that's not T1-T6
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Generic packet should expire the flow, causing it to be processed without T5", TD_RET_OK | TD_RET_FLAG_USED_T6_WITHOUT_T5, ret );
        res &= TestIntEq( "FlowInfo should be processed and removed", NULL, flow_info );
    }

    // now that the flow is expired, another handshake should go through no problem
    res &= TestProcessing_Helper_FullHandshake( 12345 );

    return res;
}

static int TestProcessing_Helper_OooPacketGenerator( int num_of_packets )
{
    int res = 1;

    uint32_t TEST_IP = 67890;
    Packet packet;
    UTH_FillPacket( &packet,  TEST_IP, 3333, TEST_IP_2, 2222, 0, "" );  // 0 = all TCP flags clear

    for( int i=0; i<num_of_packets; i++ )
    {
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "generic: should land in ooo queue", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",            NULL,       flow_info );
    }

    return res;
}

static int TestProcessing_StressOooArray1()
{
    int res;

    res = TestProcessing_Helper_ConvolutedHandshake();

    size_t extra_packets = 17;
    res &= TestProcessing_Helper_OooPacketGenerator( extra_packets );

    {
        // create a non-zero request packet (aka T4)
        Packet packet4;
        UTH_FillPacket( &packet4, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK+TH_PUSH, "RQ" );

        // create an ACK packet (aka T5)
        Packet packet5;
        UTH_FillPacket( &packet5, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "" );

        // create response packet (aka T6)
        Packet packet6;
        UTH_FillPacket( &packet6, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // ooo queue should exist because of what happened in TestProcessing_Helper_ConvolutedHandshake()
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "So far 3 packets should have been processed", 3, flow_info->processed_packets );
        res &= TestIntNeq( "ooo should exist", NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo should have just 1 (removed) element", 1 + extra_packets, flow_info->ooo_packets_cnt );
        res &= TestIntEq( "ooo should contain 0 (active) packets",    0 + extra_packets, CountNonemptyOooPackets(flow_info) );  // 2, because SYN+ACK got processed, so it should no longer be there

    // now apply the packets in reverse order

        // send T6 - should land in ooo
        int ret = PacketHandler( &packet6, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T6) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        // ooo queue should now exist
        res &= TestIntNeq( "ooo should now exist",                NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo should contain 1 (active) packet",    1 + extra_packets, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "So far 3 packets should have been processed", 3, flow_info->processed_packets );

        // send T5 - should land in ooo
        ret = PacketHandler( &packet5, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T5) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        // ooo queue should still exist
        res &= TestIntEq( "ooo should contain 2 (active) packets",  2 + extra_packets, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "No futher progess in packet processing", 3, flow_info->processed_packets );

        // send T4 - everything should now process
        ret = PacketHandler( &packet4, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T4) should succeed",    TD_RET_OK + 2*TD_RET_CNT_OOO_PROCESSED, ret );
        res &= TestIntEq( "FlowInfo should be processed and removed", NULL, flow_info );

        // flow should no longer exit
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "FlowInfo should no longer exist", NULL, flow_info );
    }

    // now that the flow is expired, another handshake should go through no problem
    res &= TestProcessing_Helper_FullHandshake( 12345 );

    return res;
}

static int TestProcessing_StressOooArray2()
{
    int res;

    res = TestProcessing_Helper_ConvolutedHandshake();

    size_t extra_packets = 18;
    res &= TestProcessing_Helper_OooPacketGenerator( extra_packets );

    {
        // create a non-zero request packet (aka T4)
        Packet packet4;
        UTH_FillPacket( &packet4, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_ACK+TH_PUSH, "RQ" );

        // create an ACK packet (aka T5)
        Packet packet5;
        UTH_FillPacket( &packet5, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "" );

        // create response packet (aka T6)
        Packet packet6;
        UTH_FillPacket( &packet6, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_ACK, "RS" );

        // ooo queue should exist because of what happened in TestProcessing_Helper_ConvolutedHandshake()
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "So far 3 packets should have been processed", 3, flow_info->processed_packets );
        res &= TestIntNeq( "ooo should exist", NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo should have just 1 (removed) element", 1 + extra_packets, flow_info->ooo_packets_cnt );
        res &= TestIntEq( "ooo should contain 0 (active) packets",    0 + extra_packets, CountNonemptyOooPackets(flow_info) );  // 2, because SYN+ACK got processed, so it should no longer be there

    // now apply the packets in reverse order

        // send T6 - should land in ooo
        int ret = PacketHandler( &packet6, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T6) should succeed", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should exist",                NULL, flow_info );

        // ooo queue should now exist
        res &= TestIntNeq( "ooo should now exist",                NULL, flow_info->ooo_packets     );
        res &= TestIntEq( "ooo should contain 1 (active) packet",    1 + extra_packets, CountNonemptyOooPackets(flow_info) );
        res &= TestIntEq( "So far 3 packets should have been processed", 3, flow_info->processed_packets );

        // send T5 - should land in ooo
        ret = PacketHandler( &packet5, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet (T5) should overflow ooo", TD_RET_FLAG_OOO_ADDED | TD_RET_ERR, ret );
        res &= TestIntEq( "FlowInfo should no longer exist",            NULL, flow_info );
    }

    // now that the flow is expired, another handshake should go through no problem
    res &= TestProcessing_Helper_FullHandshake( 12345 );

    return res;
}

static int TestProcessing_DuplicatePacket_common( Packet* passed_packet )
{
    int res = 1;

    {
        // create a SYN packet
        Packet packet;
        UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

        // should pass
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
    }

    {
        // create a SYN+ACK packet
        UTH_FillPacket( passed_packet, TEST_IP_2, 2222, TEST_IP_1, 1111, TH_SYN+TH_ACK, "" );

        // should pass
        int ret = PacketHandler( passed_packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Processing packet should succeed",    1,       ret );
        res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );
    }

    return res;
}

static int TestProcessing_DuplicatePacket1()
{
    int res;

    {
        Packet packet;
        res = TestProcessing_DuplicatePacket_common( &packet ); // builds packet inside

        // now let's send that packet again
        LogPacket( &packet );
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "2nd SYN+ACK should just be recognised as duplicate", TD_RET_DUPLICATE_PACKET, ret );
        res &= TestIntNeq( "FlowInfo should still exist",                       NULL, flow_info );

        // now let's send that packet again, but with a different endpoint (should trigger unrelated-flow reaction)
        packet.sp = 1112;
        LogPacket( &packet );
        ret = PacketHandler( &packet, 12345, 0, NULL );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "Unrelated SYN+ACK should land in ooo", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should still exist",         NULL, flow_info );
    }

    return res;
}

static int TestProcessing_DuplicatePacket2()
{
    int res;

    {
        Packet packet;
        res = TestProcessing_DuplicatePacket_common( &packet ); // builds packet inside

        // now let's send that packet again, but with some attribute modified
        packet.payload_len = 123;   // SYN+ACK shouldn't have a length therefore we're testing it on a malformed packet, but that doesn't matter here
        LogPacket( &packet );
        /*int ret =*/ PacketHandler( &packet, 12345, 0, NULL );

        // now here it's not clear what should happen.  The way we have it implemented right now, any duplicate but different packet gets shoved into OOO,
        // where it will probably just rot until the flow is expired or something (notable difference is SYN, where it will restart the flow)
        // res &= TestIntEq( "2nd SYN+ACK should be recognised as an altered dupe", 0, ret );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntNeq( "FlowInfo should still exist", NULL, flow_info );
    }

    return res;
}

static int TestProcessing_DuplicatePacket3()
{
    int res;

    {
        Packet packet;
        res = TestProcessing_DuplicatePacket_common( &packet ); // builds packet inside

        // now let's send that packet again, but with opposite flow direction
        packet.src.address.address_un_data32[0] = TEST_IP_1;
        packet.dst.address.address_un_data32[0] = TEST_IP_2;
        packet.sp = 1111;
        packet.dp = 2222;

        LogPacket( &packet );
        int ret = PacketHandler( &packet, 12345, 0, NULL );
        FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "2nd SYN+ACK sent in reverse dir should land in ooo", TD_RET_FLAG_OOO_ADDED | TD_RET_OK, ret );
        res &= TestIntNeq( "FlowInfo should still exist",         NULL, flow_info );
    }

    return res;
}

static int TestProcessing_ExpireOldPackets1()
{
    int res = 1;

    // create a SYN packet
    Packet packet;
    UTH_FillPacket( &packet, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );

    // expects a SYN packet - should pass
    int ret = PacketHandler( &packet, 12345, 0, NULL );
    FlowInfo* flow_info = GetFlowInfoFromHT( 12345 );
    res &= TestIntEq( "Processing packet should succeed",    1,       ret );
    res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );

    // our only flow is fresh, so flow shouldn't expire
    ExpireOldFlows( GetTimestampInMicroSec(packet.ts), 12345 );
    flow_info = GetFlowInfoFromHT( 12345 );
    res &= TestIntNeq( "FlowInfo should exist",           NULL, flow_info );


    for( int i=0; i<2; i++ )
    {
        // now let's age the packet (by accelerating time) beyond timeout and pass it for another go
        packet.ts.tv_sec += FLOW_LIFETIME/MILLION;
        packet.ts.tv_usec ++;                               // we don't care about off-by-one behaviour, so don't want to enforce it in a test
        ExpireOldFlows( GetTimestampInMicroSec(packet.ts), 12345 );
        flow_info = GetFlowInfoFromHT( 12345 );
        res &= TestIntEq( "FlowInfo should be deleted",       NULL, flow_info );

        // rerunning this many times should have no further effects, but should execute fine
    }

    // clean up g_current_time (resync it to packet generator as now it equals to highest timestamp used in the test)
    {
        Packet p;
        UTH_FillPacket( &p, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );
        g_current_time = GetTimestampInMicroSec( p.ts );
    }

    return res;
}

static int TestProcessing_ExpireOldPackets2()
{
    int res = 1;

    // let's make flows
    TestProcessing_Helper_FullHandshake( 1 );
    TestProcessing_Helper_FullHandshake( 2 );
    TestProcessing_Helper_FullHandshake( 3 );
    TestProcessing_Helper_FullHandshake( 4 );
    TestProcessing_Helper_FullHandshake( 5 );

    // save current timestamp
    TimeInMicroSec current_time = GetFlowInfoFromHT(1)->packets[0].timestamp;

    // let's hack the timestamps on the SYN packets to age flows (expiration compares SYN timestamps with current time)
    GetFlowInfoFromHT(1)->packets[0].timestamp = current_time - FLOW_LIFETIME + 0;
    GetFlowInfoFromHT(2)->packets[0].timestamp = current_time - FLOW_LIFETIME + FLOW_LIFETIME/3;
    GetFlowInfoFromHT(3)->packets[0].timestamp = current_time - FLOW_LIFETIME + FLOW_LIFETIME/4;
    GetFlowInfoFromHT(4)->packets[0].timestamp = current_time - FLOW_LIFETIME + FLOW_LIFETIME/4;
    GetFlowInfoFromHT(5)->packets[0].timestamp = current_time - FLOW_LIFETIME + FLOW_LIFETIME/2;

    // don't progress time and expire flows
    int expired = ExpireOldFlows( current_time - 1, 12345 );   // -1 so the 1st packet doesn't hit expiration for sure
    res &= TestIntEq ( "Should expire this many nodes", 0, expired );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(1) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(2) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(3) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(4) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(5) );

    // progress time and expire again
    current_time += FLOW_LIFETIME/4;               // note that -1 is still in effect from previous update
    expired = ExpireOldFlows( current_time, 12345 );
    res &= TestIntEq ( "Should expire this many nodes", 1, expired );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(1) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(2) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(3) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(4) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(5) );

    // progress time and expire again
    current_time += 2;                             // again, skip over the off-by-1 matter by incrementing just beyond
    expired = ExpireOldFlows( current_time, 12345 );
    res &= TestIntEq ( "Should expire this many nodes", 2, expired );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(1) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(2) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(3) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(4) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(5) );

    // progress time and expire again
    current_time += FLOW_LIFETIME/4 - 2;           // -2 because we don't care about off-by-1 behaviour, so we don't want to enforce it in the test
    expired = ExpireOldFlows( current_time, 12345 );
    res &= TestIntEq ( "Should expire this many nodes", 1, expired );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(1) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(2) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(3) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(4) );
    res &= TestIntNeq( "FlowInfo should still exist", NULL, GetFlowInfoFromHT(5) );

    // progress time and expire again
    current_time += 2;                             // again, skip over the off-by-1 matter by incrementing just beyond
    expired = ExpireOldFlows( current_time, 12345 );
    res &= TestIntEq ( "Should expire this many nodes", 1, expired );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(1) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(2) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(3) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(4) );
    res &= TestIntEq ( "FlowInfo should be deleted",  NULL, GetFlowInfoFromHT(5) );



    // clean up g_current_time (resync it to packet generator as now it equals to highest timestamp used in the test)
    {
        Packet p;
        UTH_FillPacket( &p, TEST_IP_1, 1111, TEST_IP_2, 2222, TH_SYN, "" );
        g_current_time = GetTimestampInMicroSec( p.ts );
    }

    return res;
}





int TestProcessing()
{
    int res = 1;
    printf( "\n" ); // calling code doesn't line-feed

    printf( "Running TestProcessing_NoTcpHeader()                      \n" ); res &= TestProcessing_NoTcpHeader();
    printf( "Running TestProcessing_FlowDoesNotExist()                 \n" ); res &= TestProcessing_FlowDoesNotExist();
    printf( "Running TestProcessing_FirstPacketNotSynOrSynAck()        \n" ); res &= TestProcessing_FirstPacketNotSynOrSynAck();
    printf( "Running TestProcessing_ConvolutedHandshake()              \n" ); res &= TestProcessing_ConvolutedHandshake();
    printf( "Running TestProcessing_MultipleSyn()                      \n" ); res &= TestProcessing_MultipleSyn();

    printf( "Running TestProcessing_RestartFlowWithSalvagedOooPackets()\n" ); res &= TestProcessing_RestartFlowWithSalvagedOooPackets();
    printf( "Running TestProcessing_StressOooArray1()                  \n" ); res &= TestProcessing_StressOooArray1();
    printf( "Running TestProcessing_StressOooArray2()                  \n" ); res &= TestProcessing_StressOooArray2();

    printf( "Running TestProcessing_SecondPacketSynAckWrongDirection() \n" ); res &= TestProcessing_SecondPacketSynAckWrongDirection();
    printf( "Running TestProcessing_SecondPacketSynAck()               \n" ); res &= TestProcessing_SecondPacketSynAck();
    printf( "Running TestProcessing_SecondPacketRst()                  \n" ); res &= TestProcessing_SecondPacketRst();
    printf( "Running TestProcessing_AnyPacketRst()                     \n" ); res &= TestProcessing_AnyPacketRst();
    printf( "Running TestProcessing_FullHandshake()                    \n" ); res &= TestProcessing_FullHandshake();
    printf( "Running TestProcessing_FullHandshakeThenSyn()             \n" ); res &= TestProcessing_FullHandshakeThenSyn();

    printf( "Running TestProcessing_HappyPath1()                       \n" ); res &= TestProcessing_HappyPath1();
    printf( "Running TestProcessing_HappyPathOoo1()                    \n" ); res &= TestProcessing_HappyPathOoo1();
    printf( "Running TestProcessing_HappyPathOoo2()                    \n" ); res &= TestProcessing_HappyPathOoo2();

    printf( "Running TestProcessing_HappyPathOooT5()                   \n" ); res &= TestProcessing_HappyPathOooT5();
    printf( "Running TestProcessing_HappyPathNoT5()                    \n" ); res &= TestProcessing_HappyPathNoT5();

    printf( "Running TestProcessing_DuplicatePacket1()                 \n" ); res &= TestProcessing_DuplicatePacket1();
    printf( "Running TestProcessing_DuplicatePacket2()                 \n" ); res &= TestProcessing_DuplicatePacket2();
    printf( "Running TestProcessing_DuplicatePacket3()                 \n" ); res &= TestProcessing_DuplicatePacket3();

    printf( "Running TestProcessing_ExpireOldPackets1()                \n" ); res &= TestProcessing_ExpireOldPackets1();
    printf( "Running TestProcessing_ExpireOldPackets2()                \n" ); res &= TestProcessing_ExpireOldPackets2();

    return res;
}

