#!/bin/bash

echo "suricata"

set -x
exec suricata /suricata/config.cfg
