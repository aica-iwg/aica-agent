#!/bin/bash
# For local testing only - not necessary for the actual docker-compose
docker rm -f aica-target-clam
docker build -t aica-target-clam .
docker run --name=aica-target-clam --rm -it --cap-add SYS_ADMIN aica-target-clam