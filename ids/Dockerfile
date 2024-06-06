FROM alpine:3.19

RUN apk update && apk upgrade && \
    apk add bind-tools bash suricata syslog-ng tcpdump fprobe

COPY aica-syslog.conf /etc/syslog-ng/conf.d/aica-syslog.conf

RUN suricata-update update-sources && \
    suricata-update enable-source et/open && \
    suricata-update

COPY suricata.yaml /etc/suricata/
COPY docker_entrypoint.sh /usr/local/bin/