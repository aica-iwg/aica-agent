FROM --platform=linux/amd64 mambaorg/micromamba:1.5-alpine3.19 

USER root
ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1

RUN apk update && apk upgrade && \
    apk add \
        git \
        python3 \
        py3-pip \
        python3-dev \
        alpine-sdk \
        openssl-dev \
        libpcap-dev \
        libffi-dev \
        bash \
        sudo \
        iptables \
        wget

COPY opencanary.conf /etc/opencanaryd/opencanary.conf


USER $MAMBA_USER
COPY --chown=$MAMBA_USER:$MAMBA_USER environment-honeypot.yml /tmp/env.yml
#COPY --chown=root:root environment-honeypot.yml /tmp/env.yml
RUN micromamba install -y -n base -f /tmp/env.yml && \
    micromamba clean --all --yes

USER root
#ENTRYPOINT ["/usr/local/bin/_entrypoint.sh", "/opt/conda/bin/opencanaryd", "--dev"]