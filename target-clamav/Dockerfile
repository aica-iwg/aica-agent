FROM alpine:3

# Install iptables for forwarding (enabled in entrypoint since RO here)
RUN apk update && apk upgrade && \
    apk add openssh iptables ipset nginx bind-tools bash

# Clam AV
RUN apk --no-cache add clamav-daemon freshclam clamav-libunrar supervisor

# Allow manager to access via SSH commands
RUN ssh-keygen -A && mkdir -p /root/.ssh
COPY manager_key.pub /root/.ssh/authorized_keys
RUN chown -R root:root /root && \
  chmod 750 /root/.ssh && \
  chmod 600 /root/.ssh/authorized_keys

COPY index.html /var/www/localhost/htdocs/
COPY aica-nginx.conf /etc/nginx/http.d/default.conf
COPY docker_entrypoint.sh /usr/local/bin/
COPY eicar.com /opt/eicar.com
COPY eicartest /opt/eicartest

RUN sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
    #echo 'TCPSocket 3310' >> /etc/clamav/clamd.conf && \
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf

# this is to bootstrap the virus definitions, as trying to start clamd without
# any just causes the process to die, upon the container starting it updates
# these immediately again
RUN freshclam

RUN mkdir /run/clamav && chown clamav:clamav /run/clamav && chmod u+x /usr/local/bin/docker_entrypoint.sh
COPY etc /etc/

# EXPOSE 3310/tcp

RUN /usr/local/bin/docker_entrypoint.sh
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
# ENTRYPOINT [ "sh", "/usr/local/bin/docker_entrypoint.sh" ]