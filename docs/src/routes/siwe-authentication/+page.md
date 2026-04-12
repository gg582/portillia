---
title: SIWE Authentication
description: Use Sign-In with Ethereum (SIWE) and ENS for portable tunnel identity.
---

# SIWE Authentication

Portal supports **Sign-In with Ethereum (SIWE)** for proving ownership of tunnel names without centralized accounts or API keys.

## Overview

SIWE allows you to:

- **Claim a tunnel name** by signing a message with your Ethereum wallet
- **Prove ownership** without passwords, tokens, or a central auth server
- **Use ENS names** for human-readable, portable identity (e.g., `alice.eth`)

## How It Works

1. You choose a tunnel name (or use your ENS name)
2. Portal generates a SIWE message containing the tunnel name and relay domain
3. You sign the message with your Ethereum wallet (e.g., MetaMask, hardware wallet)
4. The signed message is sent to the relay server
5. The relay verifies the signature on-chain and grants the tunnel name

```
Wallet  -->  Sign SIWE message  -->  Portal CLI  -->  Relay server
                                                         |
                                                    Verify signature
                                                         |
                                                    Grant tunnel name
```

## ENS Integration

If you own an ENS name, you can use it directly as your tunnel name:

- `alice.eth` becomes your portable identity across relays
- No registration or DNS configuration needed
- Works with any relay in the public registry

## Configuration

```bash
# Use SIWE authentication with a specific tunnel name
portal-tunnel --auth siwe --name my-tunnel localhost:3000

# Use your ENS name
portal-tunnel --auth siwe --name alice.eth localhost:3000
```

## Without SIWE

SIWE is optional. Without it:

- Tunnel names are assigned on a first-come, first-served basis
- No ownership guarantee — anyone can claim an unused name
- Suitable for temporary or throwaway tunnels

## Next Steps

- [Security Model](/security-model) — understand Portal's encryption and trust model
- [Configuration](/configuration) — full configuration reference
