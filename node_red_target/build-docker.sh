#!/bin/bash
# For local testing only - not necessary for the actual docker-compose
docker rm -f node-red-target
docker build -t node-red-target .
docker run --rm -e "NODE_RED_CREDENTIAL_SECRET=your_secret_goes_here" -e "FLOWS=flows.json" -p 1880:1880 -v `pwd`:/data --name node-red node-red-target