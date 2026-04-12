---
title: What is Portal?
description: An introduction to Portal — a permissionless localhost tunnel and public relay system.
---

# What is Portal?

Portal is an open-source localhost tunnel that publishes local services to the public internet through relay servers — without login, billing, or cloud SaaS dependencies.

## Key Properties

- **Permissionless** — no account or API key required. Run the command and you're live.
- **End-to-end TLS** — tenant TLS terminates locally with MITM detection; relays never see plaintext.
- **Self-hostable** — use the public relay registry, discovered relay pools with failover, or run your own relay.
- **Raw TCP** — carries HTTP, gRPC, WebSocket, and arbitrary TCP protocols without SSH or WebSocket overlays.

## How It Works

1. You start a local app (e.g., `localhost:3000`).
2. You run `portal-tunnel` which connects to a relay server.
3. The relay assigns a public HTTPS URL (e.g., `your-name.relay.example.com`).
4. Incoming traffic is forwarded through the relay to your local app via an encrypted tunnel.

## When to Use Portal

| Use Case | Example |
|----------|---------|
| Share a dev server | Show a colleague your local branch |
| Webhook development | Receive Stripe/GitHub webhooks locally |
| Demo to clients | Temporary public URL for a staging app |
| IoT / edge devices | Expose a device behind NAT |

## Next Steps

- [Prerequisites](/prerequisites) — what you need before installing
- [Getting Started](/getting-started) — install and run your first tunnel
