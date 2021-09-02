FROM alpine:3

# Install iptables for forwarding (enabled in entrypoint since RO here)
RUN apk update && apk upgrade && \
    apk add openssh iptables ipset nginx bind-tools bash

# Allow manager to access via SSH commands
RUN ssh-keygen -A && mkdir -p /root/.ssh
COPY manager_key.pub /root/.ssh/authorized_keys
RUN chown -R root:root /root && \
  chmod 750 /root/.ssh && \
  chmod 600 /root/.ssh/authorized_keys

COPY docker_entrypoint.sh /usr/local/bin/