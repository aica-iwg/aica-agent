FROM graylog/graylog:4.3-jre11

COPY syslog-input-graylog.json /usr/share/graylog/data/contentpacks/syslog-input-graylog.json
ENV GRAYLOG_CONTENT_PACKS_AUTO_INSTALL syslog-input-graylog.json
ENV GRAYLOG_CONTENT_PACKS_LOADER_ENABLED true
ENV GRAYLOG_CONTENT_PACKS_DIR data/contentpacks