FROM node:18-bullseye

WORKDIR /
RUN mkdir -p /coraza/coreruleset && mkdir -p /coraza/sites/localhost && \
    git clone https://github.com/coreruleset/coreruleset.git /coraza/coreruleset && \ 
    cp /coraza/coreruleset/crs-setup.conf.example /coraza/sites/localhost/1_crs_setup.conf
COPY config/Caddyfile /coraza/Caddyfile
COPY config/coraza/coraza.conf /coraza/coraza.conf
COPY ./caddy /usr/bin/caddy

RUN chmod 700 /usr/bin/caddy && mkdir -p /var/log/caddy && \ 
    git clone https://github.com/juice-shop/juice-shop.git --depth 1

# ARG CACHEBUST=1 # For debugging
WORKDIR /juice-shop
RUN npm i -g typescript ts-node && \
    npm install --omit=dev --unsafe-perm && \
    npm dedupe && \
    rm -rf frontend/node_modules && rm -rf frontend/.angular && rm -rf frontend/src/assets

RUN mkdir logs && \
    rm data/chatbot/botDefaultTrainingData.json || true && \
    rm ftp/legal.md || true && \
    rm i18n/*.json || true

COPY config/aica-config.yml /juice-shop/config/aica-config.yml
ENV NODE_ENV=aica-config

COPY ./docker_entrypoint.sh /juice-shop/entrypoint.sh
RUN chmod 700 /juice-shop/entrypoint.sh
#EXPOSE 3000 # For debugging
EXPOSE 80
ENTRYPOINT [ "/juice-shop/entrypoint.sh" ]