FROM nodered/node-red:3.1.0

# Copy package.json to the WORKDIR so npm builds all
# of your added nodes modules for Node-RED
COPY package.json .
RUN npm install --unsafe-perm --no-update-notifier --no-fund --only=production

WORKDIR /data
RUN npm install node-red-contrib-modbus@5.23.2
RUN npm install node-red-dashboard@3.2.0
WORKDIR /usr/src/node-red

# Additional non-NodeRed related setup
USER root
RUN apk update && apk upgrade && \
    apk add openssh && \
    chmod u+s /bin/su
RUN echo "root:targetrootpassword" | chpasswd && \
    mkdir /var/log/node-red && chown node-red:node-red /var/log/node-red/ && \
    ssh-keygen -A && mkdir -p /root/.ssh

# This is a really jank way of doing this, but we're not really running any additional services,
# it's just some commands, so using a CMD or ENTRYPOINT doesn't make sense.
COPY docker_entrypoint.sh /usr/local/bin/
RUN sed -i '1 a sh /usr/local/bin/docker_entrypoint.sh' /usr/src/node-red/entrypoint.sh && \
    chmod +x /usr/local/bin/docker_entrypoint.sh

USER node-red

# Copy your Node-RED project files into place
# NOTE: This will only work if you DO NOT later mount /data as an external volume.
#       If you need to use an external volume for persistence then
#       copy your settings and flows files to that volume instead.
COPY settings.js /data/settings.js
COPY flows.json /data/flows.json

# Add extra nodes via your package.json file