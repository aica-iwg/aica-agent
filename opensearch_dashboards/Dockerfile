FROM opensearchproject/opensearch-dashboards:2.16.0

USER root 

COPY opensearch_dashboards.yml /usr/share/opensearch-dashboards/config/opensearch_dashboards.yml

COPY aica-dashboard.crt /usr/share/opensearch-dashboards/config/aica-dashboard.crt
COPY aica-dashboard.key /usr/share/opensearch-dashboards/config/aica-dashboard.key
COPY --from=common rootCA.crt /usr/share/opensearch-dashboards/config/rootCA.crt

RUN chown opensearch-dashboards:opensearch-dashboards /usr/share/opensearch-dashboards/config/*.crt
RUN chown opensearch-dashboards:opensearch-dashboards /usr/share/opensearch-dashboards/config/*.key

COPY docker_entrypoint-local.sh /usr/local/bin/docker_entrypoint-local.sh

RUN chmod +x /usr/local/bin/docker_entrypoint-local.sh

USER 1000 
CMD /usr/local/bin/docker_entrypoint-local.sh