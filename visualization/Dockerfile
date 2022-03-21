FROM grafana/grafana:8.2.3

USER root

RUN apk --no-cache update && \
    apk --no-cache upgrade && \
    apk --no-cache add prometheus sudo supervisor

COPY grafana.ini /etc/grafana/grafana.ini
COPY datasources.yml /etc/grafana/provisioning/datasources/datasources.yml
COPY dashboard.yml /etc/grafana/provisioning/dashboards/dashboard.yml
COPY dashboard-django.json /etc/grafana/provisioning/dashboards/django.json
COPY dashboard-rabbit.json /etc/grafana/provisioning/dashboards/rabbit.json
COPY dashboard-prometheus.json /etc/grafana/provisioning/dashboards/prometheus.json

COPY prometheus.yml /etc/prometheus/prometheus.yml

COPY supervisor.ini /etc/supervisor.d/supervisor.ini

COPY docker_entrypoint.sh /usr/local/bin/docker_entrypoint.sh
RUN chmod +x /usr/local/bin/docker_entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker_entrypoint.sh"]