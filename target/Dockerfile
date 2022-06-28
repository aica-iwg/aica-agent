FROM alpine:3
USER root
# Install iptables for forwarding (enabled in entrypoint since RO here)
RUN apk update && apk upgrade && \
    apk add openssh iptables ipset nginx bind-tools bash vim zip

# Clam AV
RUN apk --no-cache add clamav-daemon freshclam clamav-libunrar supervisor clamav

# Allow manager to access via SSH commands
RUN ssh-keygen -A && mkdir -p /root/.ssh
COPY manager_key.pub /root/.ssh/authorized_keys
RUN chown -R root:root /root && \
  chmod 750 /root/.ssh && \
  chmod 600 /root/.ssh/authorized_keys

COPY index.html /var/www/localhost/htdocs/
COPY aica-nginx.conf /etc/nginx/http.d/default.conf
COPY docker_entrypoint.sh /usr/local/bin/
COPY clamonacc.sh /usr/local/bin
COPY test-files /opt/test-files

RUN sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf

# this is to bootstrap the virus definitions, as trying to start clamd without
# any just causes the process to die, upon the container starting it updates
# these immediately again
RUN freshclam
RUN addgroup -S appuser && adduser -D -s /bin/bash appuser -G appuser 

# The malware.zip.malz is a zip archive that is not in the repo that is used to generate
# clamav logs. Please remove a line containing that file name if you see it.
RUN mkdir /run/clamav && mkdir /root/quarantine && \
    chown root:root /run/clamav && chown root:root /root/quarantine && \
    chown appuser:appuser /opt/test-files/malware.zip.malz /opt/test-files/eicar.com && \
    chmod +x /usr/local/bin/docker_entrypoint.sh /usr/local/bin/clamonacc.sh

COPY etc /etc/

# Only uncomment when using the build-docker.sh script
# CMD ["sh", "-c", "supervisord -c /etc/supervisord.conf && sh /usr/local/bin/docker_entrypoint.sh"]