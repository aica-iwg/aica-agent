FROM kalilinux/kali-rolling:latest 

USER root

# Use the Cloudflare Mirror (see http://http.kali.org/README?mirrorlist)
ENV APT_MIRROR="kali.download/kali/"
RUN sed --in-place --regexp-extended "s#http.kali.org/kali#${APT_MIRROR}#g" /etc/apt/sources.list

# Recommend kali-linux-headless package, but very large so not installing here
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        build-essential \
        hydra \
        nikto \
        nmap \
        openssh-server \
        python3-dev \
        python3-pip \
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
