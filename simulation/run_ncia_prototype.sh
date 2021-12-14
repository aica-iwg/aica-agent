#!/bin/bash

# Run the scenario
PYTHONPATH=$PWD python3 scenarios/ncia_prototype/ncia_prototype.py

# Copy the resulting messages information
cp messages.json tools/NwVis/assets

# Serve the resulting visualization
cd tools/NwVis/
python -m http.server 8080