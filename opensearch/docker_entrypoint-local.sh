#!/bin/bash

USERFILE=/usr/share/opensearch/plugins/opensearch-security/securityconfig/internal_users.yml

# kibana server user must be "kibanaserver"
hash=$(plugins/opensearch-security/tools/hash.sh -env OS_DASHBOARD_SERVER_PASSWORD)
sed -i "s#OS_DASHBOARD_SERVER_PASSWORD#${hash}#" ${USERFILE}

sed -i "s/OS_DASHBOARD_USER/${OS_DASHBOARD_USER}/" ${USERFILE}
hash=$(plugins/opensearch-security/tools/hash.sh -env OS_DASHBOARD_PASSWORD)
sed -i "s#OS_DASHBOARD_PASSWORD#${hash}#" ${USERFILE}

hash=$(plugins/opensearch-security/tools/hash.sh -env OPENSEARCH_INITIAL_ADMIN_PASSWORD)
sed -i "s#OS_ADMIN_PASSWORD#${hash}#" ${USERFILE}

hash=""

exec ./opensearch-docker-entrypoint.sh opensearch
