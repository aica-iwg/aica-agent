FROM --platform=linux/amd64 node:20-alpine3.20

ENV NODE_ENV=aica-config

RUN apk update && apk upgrade && \
    apk --no-cache add \
        openssh \
        iptables \
        ipset \
        nginx \
        bind-tools \
        bash \
        syslog-ng \
        clamav \
        supervisor \
        git \
        go

# Allow manager to access via SSH commands
RUN ssh-keygen -A && mkdir -p /root/.ssh
COPY manager_key.pub /root/.ssh/authorized_keys
RUN chown -R root:root /root && \
    chmod 750 /root/.ssh && \
    chmod 600 /root/.ssh/authorized_keys

RUN wget https://secure.eicar.org/eicar.com.txt -O /tmp/eicar.com.txt

# This is to bootstrap the virus definitions, as trying to start clamd without
# any just causes the process to die, upon the container starting it updates
# these immediately again.
COPY clamonacc.sh /usr/local/bin
COPY etc/clamav /etc/clamav/
RUN sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf && \
    freshclam && \
    mkdir /run/clamav && mkdir /root/quarantine && \
    chown root:root /run/clamav && chown root:root /root/quarantine && \
    chmod +x /usr/local/bin/clamonacc.sh

WORKDIR /root
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.2 && \
    /root/go/bin/xcaddy build --with github.com/corazawaf/coraza-caddy/v2 && \
    mkdir -p /coraza/coreruleset && mkdir -p /coraza/sites/localhost && \
    git clone https://github.com/coreruleset/coreruleset.git /coraza/coreruleset && \ 
    cp /coraza/coreruleset/crs-setup.conf.example /coraza/sites/localhost/1_crs_setup.conf

RUN git clone https://github.com/juice-shop/juice-shop.git --depth 1 --branch v17.0.0 && \
    mkdir -p /var/log/juice/ && \
    touch /var/log/juice/juiceshop.log && \
    touch /var/log/juice/juiceshop.err.log

WORKDIR /root/juice-shop
RUN npm i -g typescript@5.4.5 ts-node@10.9.2 && \
    npm install --omit=dev --unsafe-perm && \
    npm dedupe && \
    mkdir logs && \
    rm -rf frontend/node_modules && rm -rf frontend/.angular && rm -rf frontend/src/assets && \
    rm -f data/chatbot/botDefaultTrainingData.json ftp/legal.md i18n/*.json

COPY etc/aica-config.yml /juice-shop/config/aica-config.yml

COPY etc/supervisor.d /etc/supervisor.d/
COPY etc/supervisord.conf /etc/supervisord.conf

COPY index.html /var/www/localhost/htdocs/
COPY aica-nginx.conf /etc/nginx/http.d/default.conf
COPY aica-syslog.conf /etc/syslog-ng/conf.d/aica-syslog.conf

COPY etc/Caddyfile /coraza/Caddyfile
COPY etc/coraza/coraza.conf /coraza/coraza.conf

COPY docker_entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker_entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/docker_entrypoint.sh" ]