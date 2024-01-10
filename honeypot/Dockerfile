FROM alpine:3.19

ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1

RUN apk update && apk upgrade && \
    apk add git python3 py3-pip python3-dev alpine-sdk openssl-dev libpcap-dev libffi-dev bash sudo iptables 

COPY requirements.txt .
RUN python3 -m venv canary && \
    bash -c "source canary/bin/activate && pip install -Ur requirements.txt"

COPY opencanary.conf /etc/opencanaryd/opencanary.conf