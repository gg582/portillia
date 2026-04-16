---
title: Getting Started
description: Install Portal and expose your first local service to the internet.
---

# Getting Started

This guide walks you through installing Portal and exposing your first local service to the public internet in under a minute.

## Prerequisites

- A local application running on any port (e.g., a web server on port 3000)
- macOS, Linux, or Windows
- Internet connectivity

## Install the CLI

### macOS / Linux

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
```

### Windows (PowerShell)

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
```

The installer downloads the `portal` binary and places it in your PATH. No configuration file is created — Portal works out of the box.

## Updating the CLI

Already have Portal installed? Update to the latest version with a single command:

```bash
portal update
```

Portal checks for the latest GitHub release, downloads the new binary, verifies its SHA256 checksum, and replaces the current executable in place. If you're already on the latest version, it simply reports that no update is needed.

You can check the currently installed version at any time:

```bash
portal version
```

## Expose Your First App

Start a local application (or use any existing one), then run:

```bash
portal expose 3000
```

Replace `3000` with whatever port your application is running on. Portal accepts:
- A bare port: `3000` (resolves to `127.0.0.1:3000`)
- A host:port: `localhost:8080`
- A URL: `http://127.0.0.1:3000`

Portal will output a public HTTPS URL like:

```text
https://your-name.relay.example.com
```

Open that URL in any browser — you're now accessing your local app through an encrypted tunnel.

## What Just Happened?

When you ran `portal expose`:

1. **Identity created** — Portal generated a signing identity at `./identity.json` (reuse it across runs to keep the same address)
2. **Relay discovery** — Portal found available public relays from the official registry
3. **Lease registered** — Your service was registered with a relay using SIWE (Sign-In with Ethereum) authentication
4. **Reverse session** — A persistent connection was established from your machine to the relay
5. **TLS provisioned** — The relay provided certificate signing, but TLS terminates locally on your machine (end-to-end encryption)

The relay never sees your plaintext traffic. See [Concepts](/concepts) to understand how this works.

## Customizing Your Tunnel

### Set a custom hostname

```bash
portal expose 3000 --name myapp
```

Your app will be available at `myapp.relay.example.com`.

### Use a specific relay

```bash
portal expose 3000 --relays https://portal.example.com --discovery=false
```

### Expose a TCP service (e.g., Minecraft)

```bash
portal expose localhost:25565 --name minecraft --tcp
```

This allocates a dedicated TCP port on the relay — no TLS wrapping, perfect for game servers.

### Multi-service HTTP routing

```bash
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173
```

Routes are matched longest-prefix-first. The `/api` prefix is stripped before proxying.

## Next Steps

- **[Concepts](/concepts)** — Understand Portal's trustless relay model and end-to-end encryption
- **[CLI Reference](/cli-reference)** — Complete command and flag documentation
- **[Deployment](/deployment)** — Run your own relay server
