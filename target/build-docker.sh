#!/bin/bash
# For local testing only - not necessary for the actual docker-compose
docker rm -f aica-target
docker build -t aica-target .
docker run --name=aica-target --rm -it --cap-add SYS_ADMIN aica-target
