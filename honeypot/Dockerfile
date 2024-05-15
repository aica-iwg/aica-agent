FROM mambaorg/micromamba:alpine3.19
#FROM alpine:3.19


USER root
ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1

RUN apk update && apk upgrade && \
    apk add git python3 py3-pip python3-dev alpine-sdk openssl-dev libpcap-dev libffi-dev bash sudo iptables


USER $MAMBA_USER
COPY --chown=$MAMBA_USER:$MAMBA_USER environment-honeypot.yml /tmp/env.yml
#COPY --chown=root:root environment-honeypot.yml /tmp/env.yml
RUN micromamba install -y -n base -f /tmp/env.yml && \
    micromamba clean --all --yes
COPY opencanary.conf /etc/opencanaryd/opencanary.conf
