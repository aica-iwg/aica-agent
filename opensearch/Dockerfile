FROM opensearchproject/opensearch:2.16.0

USER root 

RUN yum install -y openssl

COPY opensearch.yml /usr/share/opensearch/config/

COPY aica-admin.crt /usr/share/opensearch/config/
COPY aica-admin.key /usr/share/opensearch/config/
COPY aica-node.crt /usr/share/opensearch/config/
COPY aica-node.key /usr/share/opensearch/config/
COPY --from=common rootCA.crt /usr/share/opensearch/config/

RUN chown opensearch:opensearch /usr/share/opensearch/config/*.crt
RUN chown opensearch:opensearch /usr/share/opensearch/config/*.key

COPY internal_users.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
COPY roles.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
COPY action_groups.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
COPY allowlist.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
COPY nodes_dn.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
COPY roles_mapping.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
COPY tenants.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
COPY whitelist.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
COPY config.yml /usr/share/opensearch/plugins/opensearch-security/securityconfig/
RUN chown -R opensearch:opensearch /usr/share/opensearch/plugins/opensearch-security/securityconfig/

COPY docker_entrypoint-local.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker_entrypoint-local.sh

USER opensearch 

CMD /usr/local/bin/docker_entrypoint-local.sh 