FROM neo4j:5.14-community

RUN wget -O /var/lib/neo4j/plugins/gds.jar https://github.com/neo4j/graph-data-science/releases/download/2.5.5/neo4j-graph-data-science-2.5.5.jar && \
    wget -O /var/lib/neo4j/plugins/apoc.jar https://github.com/neo4j/apoc/releases/download/5.14.0/apoc-5.14.0-core.jar

RUN mkdir /graph_data && chown neo4j /graph_data

COPY *.graphml /graph_data