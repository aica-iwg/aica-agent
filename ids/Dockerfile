FROM dtagdevsec/suricata:2006

RUN apk update && apk add bind-tools bash

RUN suricata-update update-sources && suricata-update enable-source et/open && suricata-update

COPY docker_entrypoint.sh /usr/local/bin/