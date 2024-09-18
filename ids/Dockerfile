FROM alpine:3.20

RUN apk update && apk upgrade && \
    apk add \
        bind-tools \
        bash \
        ca-certificates \
        openjdk17 \
        suricata \
        tcpdump \
        fprobe \
        wget

# Bundled JDK won't work with Alpine because Alpine doesn't include glibc
ENV LS_JAVA_HOME /usr/lib/jvm/default-jvm
RUN wget https://artifacts.elastic.co/downloads/logstash/logstash-8.15.1-linux-x86_64.tar.gz && \
    tar xzf logstash-8.15.1-linux-x86_64.tar.gz && \
    ln -s logstash-8.15.1 logstash && \
    /logstash/bin/logstash-plugin install logstash-output-opensearch

COPY logstash.conf logstash/ 

RUN suricata-update update-sources && \
    suricata-update enable-source et/open && \
    suricata-update

COPY suricata.yaml /etc/suricata/
COPY docker_entrypoint.sh /usr/local/bin/