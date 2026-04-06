#!/bin/bash
set -e

docker pull ghcr.io/gosuda/portal-tunnel:latest
docker compose down portal
docker compose up -d portal
bash nginx_deploy.sh
