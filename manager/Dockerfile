FROM python:3.9-bullseye

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONIOENCODING UTF-8
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND noninteractive

ARG nmap_ver=7.93
ARG build_rev=2


WORKDIR /usr/src/app

RUN --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install apt-utils && \
    apt-get -y install \
        supervisor \
        postgresql \
        python3 \
        python3-pip \
        python3-wheel \
        python3-venv \
        python3-setuptools \
        bash \
        cmake \
        libgeos-dev \
        libtool \
        autoconf \
        ca-certificates \
        libpcap-dev \
        build-essential \
        libssl-dev \
	liblua5.4-0  \
        liblua5.4-dev \
	linux-headers-generic  \
	openssl \
        libssl-dev\
        fprobe \
        git \
        gcc \
        g++ \
        python3-dev \
        musl-dev \
        tcpdump \
        net-tools \
        vim\
        curl

COPY requirements.txt .

RUN python3 -m venv /opt/venv && \
        /opt/venv/bin/pip3 --no-cache install -qU pip

RUN python3 -m venv /opt/venv && \
        /opt/venv/bin/pip3 --no-cache install -qUr requirements.txt

# Install dependencies
RUN curl -fL -o /tmp/nmap.tar.bz2 \
         https://nmap.org/dist/nmap-${nmap_ver}.tar.bz2 \
 && tar -xjf /tmp/nmap.tar.bz2 -C /tmp \
 && cd /tmp/nmap* 


#old nmap-7.8 crashes AICA workers resulting in: nmap: Target.cc:503: void Target::stopTimeOutClock(const timeval*): Assertion `htn.toclock_running == true' failed
#patch nmap-7.93 to make it building on Debian Bullseye (https://github.com/nmap/nmap/commit/d6bea8dcdee36a3902cece14097993350306f1b6)
RUN cd /tmp/nmap* \
    && sed -i '/#if OPENSSL_API_LEVEL < 10100/c\#if OPENSSL_VERSION_NUMBER < 0x10100000L' /tmp/nmap-${nmap_ver}/ncat/http_digest.c 


RUN cd /tmp/nmap* \
    &&  ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --mandir=/usr/share/man \
        --infodir=/usr/share/info \
        --without-zenmap \
        --without-nmap-update \
        --with-openssl \
        --with-liblua=/usr/include 

RUN cd /tmp/nmap* \
    && make \
    && make install 
    
 #&& rm -rf /tmp/nmap*

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
COPY fprobe /etc/default/

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

