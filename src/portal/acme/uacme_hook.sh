#!/bin/sh
# uacme DNS-01 hook script
# Usage: ./hook <challenge_type> <domain> <token> <key_auth>

COMMAND=$1
DOMAIN=$2
TOKEN=$3
KEY_AUTH=$4

case "$COMMAND" in
    "hook")
        # uacme DNS-01 hook: add TXT record
        # We rely on our existing Cloudflare provider logic
        # For now, we print to stdout, which uacme handles
        echo "_acme-challenge.$DOMAIN"
        echo "$KEY_AUTH"
        exit 0
        ;;
    "cleanup")
        # cleanup TXT record
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
