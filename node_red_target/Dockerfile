# https://nodered.org/docs/getting-started/docker
# TODO: Consider specifying a version with known exploits that can be logged. Couldn't find anything
#       immediately available except CVE-2021-21297, which is prototype pollution, but no available poc.
FROM nodered/node-red

# Copy package.json to the WORKDIR so npm builds all
# of your added nodes modules for Node-RED
COPY package.json .
RUN npm install --unsafe-perm --no-update-notifier --no-fund --only=production

WORKDIR /data
RUN npm install node-red-contrib-modbus
# Path traversal vulnerability - https://github.com/advisories/GHSA-2hw7-mxvj-m455
RUN npm install node-red-dashboard@2.26.0 

WORKDIR /usr/src/node-red 

# Copy your Node-RED project files into place
# NOTE: This will only work if you DO NOT later mount /data as an external volume.
#       If you need to use an external volume for persistence then
#       copy your settings and flows files to that volume instead.
COPY settings.js /data/settings.js
COPY flows.json /data/flows.json

# Additional non-NodeRed related setup
USER root
COPY docker_entrypoint.sh /usr/local/bin/

RUN apk update && apk upgrade && \
    apk add openssh && \
    chmod u+s /bin/su
RUN echo "root:targetrootpassword" | chpasswd && \
    mkdir /var/log/node-red && chown node-red:node-red /var/log/node-red/ && \
    ssh-keygen -A && mkdir -p /root/.ssh && \
    chmod +x /usr/local/bin/docker_entrypoint.sh 

# This is a really jank way of doing this, but we're not really running any additional services,
# it's just some commands, so using a CMD or ENTRYPOINT doesn't make sense.
RUN sed -i '1 a sh /usr/local/bin/docker_entrypoint.sh' /usr/src/node-red/entrypoint.sh

USER node-red
# Add extra nodes via your package.json file but you can also add them here