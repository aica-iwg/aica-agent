FROM alpine:3

RUN apk update && apk upgrade && \
    apk add bind-tools bash suricata

RUN suricata-update update-sources && \
    suricata-update enable-source et/open && \
    suricata-update

COPY docker_entrypoint.sh /usr/local/bin/