FROM alpine:3.18

RUN apk update && apk upgrade && \
    apk add nmap nmap-scripts bash openssh && \
    ssh-keygen -A

RUN adduser -D ssh_user

COPY docker_entrypoint.sh /usr/local/bin/