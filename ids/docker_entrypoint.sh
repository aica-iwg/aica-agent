#!/bin/sh

# Switch home net as required
sed -i "s#HOME_NET: \"\[\]\"#HOME_NET: \"\[${HOME_NET}]\"#" /etc/suricata/suricata.yaml

# Start Netflow exporter
fprobe -fip -i ${SURICATA_IF} localhost:2055

# Start Suricata
suricata -D -i ${SURICATA_IF}

# Start Logstash to Forward Suricata Logs to Opensearch
logstash/bin/logstash -f /logstash/logstash.conf

tail -f /dev/null
