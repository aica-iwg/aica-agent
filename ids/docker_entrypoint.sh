#!/bin/sh

# Start Syslog
syslog-ng

# Switch home net to just target
TARGET_IP=`dig +short target | grep '^[.0-9]*$'`
TARGET_IP_ESC=`echo $TARGET_IP | sed s/'\.'/'\\\.'/g`
sed -i 's/HOME_NET: "\[192\.168\.0\.0\/16,10\.0\.0\.0\/8,172\.16\.0\.0\/12\]"/HOME_NET: "\['${TARGET_IP_ESC}'\/32\]"/' \
  /etc/suricata/suricata.yaml

# Start Suricata
suricata --af-packet -i eth0 host ${TARGET_IP}
