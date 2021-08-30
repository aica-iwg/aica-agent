FROM nginx:1

# Allow manager to access via SSH commands
RUN apt-get -y update && \
  apt-get -y upgrade && \
  apt-get -y install ssh
RUN mkdir -p /root/.ssh
COPY manager_key.pub /root/.ssh/authorized_keys
RUN chown -R root:root /root && \
  chmod 750 /root/.ssh && \
  chmod 600 /root/.ssh/authorized_keys

# Install iptables for forwarding (enabled in entrypoint since RO here)
RUN apt-get -y install iptables ipset dnsutils

COPY docker_entrypoint.sh /usr/local/bin/