#!/bin/sh

# Start Syslog
syslog-ng

# Switch home net as required 
sed -i "s#HOME_NET: \"\[\]\"#HOME_NET: \"\[${HOME_NET}]\"#" /etc/suricata/suricata.yaml

# Start netflow exporter
fprobe -fip -i ${SURICATA_IF} manager:2055

# Start Suricata
suricata -i ${SURICATA_IF} 
