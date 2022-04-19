FROM python:3-buster

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONIOENCODING UTF-8
ENV PYTHONUNBUFFERED 1
ENV CRYPTOGRAPHY_DONT_BUILD_RUST 1

WORKDIR /usr/src/app

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install apt-utils && \
    apt-get -y install \
        nmap \
        supervisor \
        postgresql \
        python3 \
        python3-pip \
        python3-wheel \
        python3-venv \
        python3-setuptools \
        bash \
        cmake \
        libtool \
        autoconf \
        git \
        gcc \
        g++ \
        python3-dev \
        musl-dev

COPY requirements.txt .

RUN python3 -m venv /opt/venv && \
        /opt/venv/bin/pip3 --no-cache install -qU pip

RUN python3 -m venv /opt/venv && \
        /opt/venv/bin/pip3 --no-cache install -qUr requirements.txt

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

COPY supervisor.conf /etc/supervisor/conf.d

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