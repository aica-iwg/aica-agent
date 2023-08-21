FROM alpine:3.18

COPY requirements.txt .
RUN apk update && apk upgrade && \
    apk add \
        nmap \
        nmap-scripts \
        bash \
        openssh \
        chromium \
        chromium-chromedriver \
        py3-pip \
        build-base \
        python3-dev \
        libffi-dev && \
    pip install -U pip wheel && \
    pip install -Ur requirements.txt && \
    ssh-keygen -A

RUN adduser -D ssh_user

COPY tests/ /root/tests

COPY docker_entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker_entrypoint.sh