#!/bin/sh

echo "kali:attackersshpassword" | chpasswd
sed -i '/AllowTcpForwarding/d' /etc/ssh/sshd_config

/usr/sbin/sshd -Def /etc/ssh/sshd_config

tail -f /dev/null