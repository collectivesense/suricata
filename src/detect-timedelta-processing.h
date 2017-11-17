#pragma once

#include "suricata-common.h"
#include "detect-timedelta-common.h"
#include "detect-timedelta-flow.h"

////////////////////////////////////////////////////////////////////////////////
//
// API
//
////////////////////////////////////////////////////////////////////////////////

int  PacketHandler( const Packet* packet, FlowId flow_id, size_t ooo_packets_cnt, OooPacket ooo_packets[FLOWINFO_NUM_OF_OOOPACKETS] );