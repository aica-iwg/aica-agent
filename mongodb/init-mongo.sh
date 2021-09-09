set -e

mongo admin <<EOF
db.createUser(
    {
        user: "$MONGO_INITDB_ROOT_USER",
        pwd: "$MONGO_INITDB_ROOT_PASS",
        roles: [ { role: "root", db: "admin" } ]
    }
)
EOF

mongo $MONGO_INITDB_DATABASE << EOF
db.createUser(
    {
        user: "$MONGO_INITDB_USER",
        pwd: "$MONGO_INITDB_PASS",
        roles: [ { role: "readWrite", db: "$MONGO_INITDB_DATABASE" } ]
    }
)
EOF