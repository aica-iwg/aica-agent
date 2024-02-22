FROM kalilinux/kali-rolling:latest 

USER root

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        build-essential \
        chromium \
        chromium-driver \
        kali-linux-headless \
        libffi-dev \
        openssh-server \
        python3-dev \
        python3-pip \
        python3-selenium \
        python3-venv

RUN ssh-keygen -A

COPY docker_entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker_entrypoint.sh

RUN useradd kali

USER kali

WORKDIR /home/kali

COPY requirements.txt .
RUN python3 -m venv attacker && \
    ./attacker/bin/python -m pip install -Ur requirements.txt

COPY tests/ ./tests
