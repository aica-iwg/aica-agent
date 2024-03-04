FROM mongo:7-jammy

COPY init-mongo.sh /docker-entrypoint-initdb.d/init-mongo.sh

CMD ["mongod", "--auth"]