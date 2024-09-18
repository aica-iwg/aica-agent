FROM neo4j:5.22-community

RUN wget -O /var/lib/neo4j/plugins/gds.jar https://github.com/neo4j/graph-data-science/releases/download/2.8.0/neo4j-graph-data-science-2.8.0.jar && \
    wget -O /var/lib/neo4j/plugins/apoc.jar https://github.com/neo4j/apoc/releases/download/5.22.0/apoc-5.22.0-core.jar

RUN mkdir /graph_data && chown neo4j /graph_data

COPY aica-*.json /graph_data