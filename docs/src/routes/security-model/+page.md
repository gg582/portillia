---
title: Security Model
description: How Portal ensures end-to-end encryption and prevents relay-level eavesdropping.
---

# Security Model

Portal's security model is designed so that relay operators **cannot read tunnel traffic**, even though all data passes through their servers.

## End-to-End TLS

Tunnel traffic is encrypted with TLS between the client (browser) and your local service. The relay only sees opaque TCP bytes.

```
Client (browser)  <-- TLS -->  Your local app
        |                           ^
        |     opaque TCP bytes      |
        v                           |
   Relay server  --- forwards ----->
```

The relay performs **TCP passthrough** — it connects raw TCP streams without terminating TLS.

## MITM Detection

Portal includes built-in MITM detection:

1. The tunnel client generates a TLS certificate locally
2. The certificate fingerprint is embedded in the public URL
3. Connecting clients verify the fingerprint matches the server certificate
4. Any relay-level interception would present a different certificate, triggering a mismatch

## Relay Trust Model

| What relays CAN see | What relays CANNOT see |
|---------------------|----------------------|
| Connection metadata (IP, timing) | Request/response content |
| Tunnel name and domain | HTTP headers or body |
| Traffic volume (bytes) | TLS-encrypted payload |
| Connection duration | Application-layer data |

## SIWE Authentication

Portal supports Sign-In with Ethereum (SIWE) for identity:

- Proves ownership of a tunnel name without a centralized auth server
- ENS names provide portable, human-readable identity
- No passwords or API keys stored anywhere

## Best Practices

1. **Always use HTTPS** — Portal provisions TLS certificates automatically
2. **Verify certificate fingerprints** for sensitive applications
3. **Run your own relay** if you need full control over the infrastructure
4. **Rotate tunnel names** for temporary or throwaway use cases

## Next Steps

- [Architecture](/architecture) — deep dive into Portal's internal design
- [Self-Hosting](/self-hosting) — run your own relay server
