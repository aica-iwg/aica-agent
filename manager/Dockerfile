FROM ubuntu:22.04

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONIOENCODING UTF-8
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND noninteractive

ARG build_rev=2


WORKDIR /usr/src/app

RUN --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install apt-utils && \
    apt-get -y install \
        nmap \
        supervisor \
        postgresql \
        python3 \
        python3-dev \
        python3-pip \
        python3-setuptools \
        python3-venv \
        python3-wheel \
        bash \
        cmake \
        libpq-dev \
        libgeos-dev \
        libtool \
        autoconf \
        git \
        gcc \
        g++ \
        musl-dev \
        tcpdump \
        tshark \
        net-tools \
        vim \
        curl

#Install micromamba
RUN curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest | tar -xvj bin/micromamba
COPY environment-manager.yml .
RUN bin/micromamba env create -f environment-manager.yml

# Install dependencies
RUN apt-get -y remove \
        cmake \
        libtool \
        autoconf \
        git \
        gcc \
        g++ \
        python3-dev \
        musl-dev && \
    apt-get -y autoremove && \
    apt-get -y clean

COPY supervisor.conf /etc/supervisor/conf.d/

RUN mkdir -p /root/.ssh
COPY manager_key.priv /root/.ssh/id_rsa
RUN chown -R root:root /root
RUN chmod 700 /root/.ssh
RUN chmod 600 /root/.ssh/id_rsa

# copy project
COPY . .

COPY docker_entrypoint.sh /usr/local/bin/docker_entrypoint.sh
RUN chmod +x /usr/local/bin/docker_entrypoint.sh

CMD /usr/local/bin/docker_entrypoint.sh

