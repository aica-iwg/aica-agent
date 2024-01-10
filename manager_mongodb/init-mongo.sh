set -e

mongosh admin <<EOF
db.createUser(
    {
        user: "$MONGO_INITDB_ROOT_USER",
        pwd: "$MONGO_INITDB_ROOT_PASS",
        roles: [ { role: "root", db: "admin" } ]
    }
)
EOF

mongosh $MONGO_INITDB_DATABASE << EOF
db.createUser(
    {
        user: "$MONGO_INITDB_USER",
        pwd: "$MONGO_INITDB_PASS",
        roles: [ { role: "readWrite", db: "$MONGO_INITDB_DATABASE" } ]
    }
)
EOF

mongosh $MONGO_GRAYLOG_DATABASE << EOF
db.createUser(
    {
        user: "$MONGO_GRAYLOG_USER",
        pwd: "$MONGO_GRAYLOG_PASS",
        roles: [ { role: "readWrite", db: "$MONGO_GRAYLOG_DATABASE" } ]
    }
)
EOF
