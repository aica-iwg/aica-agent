#!/usr/bin/env sh

/bin/bash -c "while [ ! -S /var/run/clamav/clamd.sock ]; do sleep 1; done"
/usr/sbin/clamonacc -F --config-file=/etc/clamav/clamd.conf --log=/var/log/clamav/clamonacc.log --move=/root/quarantine --fdpass