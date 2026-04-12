---
title: Prerequisites
description: System requirements and prerequisites for running Portal tunnel.
---

# Prerequisites

Before installing Portal, make sure your environment meets the following requirements.

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| OS | Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64) |
| Network | Outbound TCP access (no inbound ports needed) |
| Disk | ~10 MB for the binary |

## For Tunnel Users

- A local service running on a TCP port (e.g., a web server on `localhost:3000`)
- Internet connectivity to reach a relay server

No accounts, API keys, or billing setup required.

## For Relay Operators

If you plan to run your own relay server:

- A server with a public IP address
- A domain name with DNS pointing to the server
- TLS certificate (auto-provisioned via ACME/Let's Encrypt, or manually provided)
- Ports 443 (HTTPS) and optionally 80 (HTTP redirect) open

## Optional

- **ENS name** — for SIWE-based identity and portable naming
- **Ethereum wallet** — for signing SIWE authentication messages

## Next Steps

- [Getting Started](/getting-started) — install Portal and create your first tunnel
