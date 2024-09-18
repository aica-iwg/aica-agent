#!/bin/bash
set -e

if [ ! -f common/rootCA.crt ]; then
	echo "Creating Root CA..."

	openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 -keyout common/rootCA.key -out common/rootCA.crt \
				-nodes -subj "/C=US/ST=Illinois/L=Chicago/O=Argonne/OU=S3/CN=aica-ca"
fi

if [ ! -f opensearch/aica-admin.crt ]; then
	echo "Creating OpenSearch Admin Cert..."

	openssl genrsa -out opensearch/aica-admin.key 4096
	openssl req -key opensearch/aica-admin.key -new -out opensearch/aica-admin.csr \
		-sha256 -nodes -subj "/C=US/ST=Illinois/L=Chicago/O=Argonne/OU=S3/CN=aica-admin" \
		-config opensearch/opensearch-openssl.cnf -extensions req_ext
	openssl x509 -req -CA common/rootCA.crt -CAkey common/rootCA.key -in opensearch/aica-admin.csr -out opensearch/aica-admin.crt \
		-days 3650 -CAcreateserial -extfile opensearch/opensearch-openssl.cnf -extensions req_ext
fi

if [ ! -f opensearch/aica-node.crt ]; then
	echo "Creating OpenSearch Node Cert..."

	openssl genrsa -out opensearch/aica-node.key 4096
	openssl req -key opensearch/aica-node.key -new -out opensearch/aica-node.csr \
		-sha256 -nodes -subj "/C=US/ST=Illinois/L=Chicago/O=Argonne/OU=S3/CN=aica-node" \
		-config opensearch/opensearch-openssl.cnf -extensions req_ext
	openssl x509 -req -CA common/rootCA.crt -CAkey common/rootCA.key -in opensearch/aica-node.csr -out opensearch/aica-node.crt \
		-days 3650 -CAcreateserial -extfile opensearch/opensearch-openssl.cnf -extensions req_ext
fi

if [ ! -f opensearch_dashboards/aica-dashboard.crt ]; then
	echo "Creating OpenSearch Dashboards Cert..."

	openssl genrsa -out opensearch_dashboards/aica-dashboard.key 4096
	openssl req -key opensearch_dashboards/aica-dashboard.key -new -out opensearch_dashboards/aica-dashboard.csr \
		-sha256 -nodes -subj "/C=US/ST=Illinois/L=Chicago/O=Argonne/OU=S3/CN=aica-dashboard" \
		-config opensearch_dashboards/dashboard-openssl.cnf -extensions req_ext
	openssl x509 -req -CA common/rootCA.crt -CAkey common/rootCA.key -in opensearch_dashboards/aica-dashboard.csr -out opensearch_dashboards/aica-dashboard.crt \
		-days 3650 -CAcreateserial -extfile opensearch_dashboards/dashboard-openssl.cnf -extensions req_ext
fi

if [ ! -f manager/aica-manager.crt ]; then
	echo "Creating Manager Cert..."

	openssl genrsa -out manager/aica-manager.key 4096
	openssl req -key manager/aica-manager.key -new -out manager/aica-manager.csr \
		-sha256 -nodes -subj "/C=US/ST=Illinois/L=Chicago/O=Argonne/OU=S3/CN=aica-manager" \
		-config manager/manager-openssl.cnf -extensions req_ext
	openssl x509 -req -CA common/rootCA.crt -CAkey common/rootCA.key -in manager/aica-manager.csr -out manager/aica-manager.crt \
		-days 3650 -CAcreateserial -extfile manager/manager-openssl.cnf -extensions req_ext
fi

rm -f */*.csr
