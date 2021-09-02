#!/bin/sh

sysctl net.ipv4.conf.all.forwarding=1
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ipset create honeypot hash:ip hashsize 4096 timeout 300
iptables-legacy -t nat -A PREROUTING -m set --match-set honeypot src -j DNAT --to-destination `dig +short honeypot`

echo "root:targetrootpassword" | chpasswd
/usr/sbin/sshd -ef /etc/ssh/sshd_config

nginx -g "daemon off;"