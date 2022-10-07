#!/usr/bin/env sh

# The node-red base image runs as the Node-RED user, and while that can be overridden,
# I would rather not meddle with that and potentially break some kind of functionality.
echo "targetrootpassword" | su root -c "/usr/sbin/sshd -ef /etc/ssh/sshd_config"