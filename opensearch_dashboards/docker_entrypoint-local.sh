#!/bin/bash

# kibana server user must be "kibanaserver"
sed -i "s/OS_DASHBOARD_SERVER_PASSWORD/${OS_DASHBOARD_SERVER_PASSWORD}/" /usr/share/opensearch-dashboards/config/opensearch_dashboards.yml

exec ./opensearch-dashboards-docker-entrypoint.sh
