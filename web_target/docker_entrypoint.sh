#!/bin/bash

node /juice-shop/build/app.js &
/usr/bin/caddy run --config /coraza/Caddyfile --adapter caddyfile --watch