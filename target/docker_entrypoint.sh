#!/bin/sh

# Start syslog
syslog-ng

# Set up iptables
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ipset create honeypot hash:ip hashsize 4096 timeout 300
ipset create allowlist hash:ip hashsize 4096 timeout 300

iptables-legacy -t nat -A PREROUTING -m set --match-set allowlist src -j ACCEPT
iptables-legacy -t nat -A PREROUTING -m set --match-set honeypot src -j DNAT --to-destination `dig +short honeypot`

# Set up SSH access
echo "root:targetrootpassword" | chpasswd
/usr/sbin/sshd -ef /etc/ssh/sshd_config

# Set up ClamAV pieces
echo "$(hostname),$(hostname -i)" > /var/log/clamav/hostinfo.txt
supervisord -c /etc/supervisord.conf &

# Start Nginx
nginx

# Start netflow exporter
fprobe -fip -i eth1 manager:2055

# Start caddy
/root/caddy run --config /coraza/Caddyfile --adapter caddyfile --watch
