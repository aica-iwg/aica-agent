FROM alpine:3.18

ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1

COPY requirements.txt .
RUN apk update && apk upgrade && \
    apk add git python3 py3-pip python3-dev alpine-sdk openssl-dev libpcap-dev libffi-dev bash sudo iptables && \
    pip install -U pip wheel && \
    pip install -Ur requirements.txt

COPY opencanary.conf /etc/opencanaryd/opencanary.conf