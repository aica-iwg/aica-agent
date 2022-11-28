FROM alpine:3.17

RUN apk update && apk upgrade && \
    apk add openssh iptables ipset nginx bind-tools bash syslog-ng clamav supervisor

# Allow manager to access via SSH commands
RUN ssh-keygen -A && mkdir -p /root/.ssh
COPY manager_key.pub /root/.ssh/authorized_keys
RUN chown -R root:root /root && \
  chmod 750 /root/.ssh && \
  chmod 600 /root/.ssh/authorized_keys

RUN wget https://secure.eicar.org/eicar.com.txt -O /tmp/eicar.com.txt

COPY clamonacc.sh /usr/local/bin
COPY etc/clamav /etc/clamav/

# This is to bootstrap the virus definitions, as trying to start clamd without
# any just causes the process to die, upon the container starting it updates
# these immediately again.
RUN sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf && \
    freshclam && \
    mkdir /run/clamav && mkdir /root/quarantine && \
    chown root:root /run/clamav && chown root:root /root/quarantine && \
    chmod +x /usr/local/bin/clamonacc.sh

COPY etc/supervisor.d /etc/supervisor.d/
COPY etc/supervisord.conf /etc/supervisord.conf

COPY index.html /var/www/localhost/htdocs/
COPY aica-nginx.conf /etc/nginx/http.d/default.conf
COPY aica-syslog.conf /etc/syslog-ng/conf.d/aica-syslog.conf

COPY docker_entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker_entrypoint.sh


