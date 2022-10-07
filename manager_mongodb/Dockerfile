FROM mongo:6.0-focal

RUN echo "vm.max_map_count=1048576" >> /etc/sysctl.conf

COPY init-mongo.sh /docker-entrypoint-initdb.d/init-mongo.sh

CMD ["mongod", "--auth"]