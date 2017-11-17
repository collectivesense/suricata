#pragma once

#include "detect-timedelta-common.h"

void TDLogDebug  ( FlowId flow_id, int indent_level, const char* fmt, ... );
void TDLogInfo   ( FlowId flow_id, int indent_level, const char* fmt, ... );
void TDLogWarning( FlowId flow_id, int indent_level, const char* fmt, ... );
void TDLogError  ( FlowId flow_id, int indent_level, const char* fmt, ... );
