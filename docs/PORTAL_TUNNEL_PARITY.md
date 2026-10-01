# portillia ↔ portal-tunnel Parity Design

Goal: bring portillia (C17 relay) to behavioral parity with
portal-tunnel (Go reference, `tunnel=10` / `discovery=9`), then bump announced
versions to `10`/`9` — **done as of Phase 4**. Reference tree: `../portal-tunnel`. portillia tree: this repo.

Version gate: the relay must announce `protocol_version` only after wire behavior
matches. `src/portal/api_server_relay.c:16,79` and the discovery announce check
(`portal-tunnel/portal/api_server.go:243-245`) reject mismatched versions, so the
bump is the last step of Phase 4.

## 1. Module mapping

| Reference module (portal-tunnel) | Responsibility | portillia counterpart | Structural gap |
|---|---|---|---|
| `portal/transport/stream_relay.go` | Reverse-session registry, claim/activate, marker framing (0x00 keepalive / 0x01 raw / 0x02 TLS+binding), relay TCP listeners | `src/portal/api_server.c` (`handle_connect` :474, reverse-session registry), `src/portal/proxy.c` | No binding-carrying activation frame; no 0x02 marker path; no `Claim(ctx, binding)` mint-on-route hook |
| `portal/transport/stream_client.go` | Tenant side of reverse session: reads marker, splits raw vs TLS | none (tenant is SDK-side; portillia only implements relay) | n/a — but relay must emit the exact frame the Go SDK parses (`stream_client.go:48-53`) |
| `portal/transport/quic_backhaul.go` | QUIC backhaul binding for stream+datagram relay | `src/portal/transport/quic_backhaul.c` | Local `cwist_yamux_*` stubs (:20-53); unidirectional pump, no real window/flow control; comment admits it is not a production stack |
| `portal/transport/datagram_relay.go` / `datagram_client.go` / `datagram_session.go` | UDP relay: flow table, idle expiry, QUIC datagram send | none (datagram relay not implemented) | Entire UDP relay path missing |
| `sdk/listener.go` (tenant SDK; reference only) | `runReverseSessionLoop` (:604), `openReverseSession` (:796) incl. reverse-TLS dial + capability auth; datagram framing (:459-486) | n/a | Relay must interoperate with this exact client loop |
| `portal/keyless/bindings.go` | BindingRegistry: Issue / FixHello / ValidateAndConsume / Discard / SweepExpired + ClientHello accumulator + `FixHelloOnWrite` | **missing** — new `src/portal/keyless/bindings.{c,h}` | Core v10 module absent |
| `portal/keyless/signer.go` | `/v1/sign` HTTP handler; `TranscriptValidator` calls `bindings.ValidateAndConsume` (:52-58) | `src/portal/keyless/server.c:189` (`handle_keyless_sign`) | Current sign handler only checks access token; no `TranscriptSignRequest` body, no binding validation, no leaseID binding |
| `portal/keyless/client.go` | Tenant-side keyless TLS termination via `keyless_tls` `t13server`; exporter access | none (SDK-side) | n/a — but relay's keyless server must satisfy the t13server signing protocol (`client.go:102-106`) |
| `portal/api_server.go` | Control API incl. announce version check (:243-245) | `src/portal/api_server.c`, `src/portal/api_server_relay.c` | Announce version rejection implemented (Phase 4); versions from `PORTILLIA_SDK_VERSION`/`PORTILLIA_DISCOVERY_VERSION` constants |
| `types/api.go:114-171` | Envelopes: `DiscoveryAnnounceRequest/Response`, `RenewResponse.ReverseEndpoint`, etc. | `include/portillia/portal/*.h`, discovery module | Envelope shapes must be re-verified field-by-field against :114-171 before bump |
| `sdk/http.go` | Routed HTTP: Host preservation (:324), `X-Forwarded-Proto: https` (:49), redirect rewriting | `src/sdk/http_runtime.c` | Host preservation + X-Forwarded-Proto done (Phase 4); redirect rewriting and X-Forwarded-For deferred |
| WireGuard overlay (tunnel 8→9) | retired | none present | Nothing to remove — verify no WG deps in build/config |
| ECH (tunnel 9→10) | removed | unknown — grep config/settings for ECH before Phase 3 | Remove if present |

## 2. Protocol change checklists

### v9 (tunnel 8→9): WireGuard relay overlay retired
- [x] Audit portillia for WireGuard overlay code: portillia **retains a functioning
      WireGuard overlay** (`rust_bridge/src/overlay.rs` via `wireguard_control`,
      `OverlayInit` in `cmd/relay-server/main.c`, WG keys in identity.json). Unlike
      the Go reference (which deleted WG entirely), these fields are live, not dead.
      Decision (Phase 4): **keep** the WG key material in identity/descriptor structs
      and JSON. Extra JSON fields are ignored by the Go side, so v9/v10 interop is
      unaffected; ripping out the overlay is out of Phase 4 scope.
- [x] Discovery version bumped to `9`; no wire change on the reverse-session path.

### v10 (tunnel 9→10): transcript-bound keyless TLS
Reference: `portal/keyless/bindings.go`, `portal/keyless/signer.go`, `portal/transport/stream_relay.go`, `portal/keyless/client.go`.

Binding lifecycle to replicate:
1. **Mint** — `BindingRegistry.Issue` (`bindings.go:32-45`): relay mints 16 random bytes per routed connection at claim time; entry = `{leaseID, expiresAt(now+TTL), helloHash}`; `helloHash` empty until fixed.
2. **Deliver** — relay writes activation frame on the reverse session: `markerTLSStart(0x02)` + 16-byte binding (`stream_relay.go:378-381`, `activateWithMarker`); raw path uses bare `0x01` (`:384`). Keepalive `0x00` (`:439`). Tenant parses at `stream_client.go:48-53`.
3. **Fix** — tenant pins the binding to the first ClientHello bytes it forwards: `FixHelloOnWrite` (`bindings.go:183-222`) with the TLS-record accumulator (`:124-179`, max CH 128 KiB, handshake content type 22, first msg type 1). `FixHello` (:48-66) rejects unknown/expired/already-fixed.
4. **Consume** — `/v1/sign` handler (`signer.go:77-110`) decodes `signrpc.TranscriptSignRequest`, `TranscriptValidator` (:52-58) requires a verified leaseID from context and calls `ValidateAndConsume` (`bindings.go:69-96`): 16-byte binding, non-empty ClientHello, entry exists & unexpired, leaseID match, `sha256(ClientHello)` equals fixed hash — then `delete` (single-use).
5. **Cleanup** — `Discard` for bindings never delivered to a live stream (`:99-103`); `SweepExpired` periodic sweep (`:106-114`).

TLS termination:
- Tenant TLS terminates at the SDK through `keyless_tls` `t13server` (`client.go:27,102-106`), with the relay as keyless signer; exporter available per RFC 8446 §7.5 (`client.go:157`). portillia needs no t13server itself — its `/v1/sign` must implement the signer side of that protocol (`signer.go` + `signrpc` envelope) and the binding check above.
- ECH removed (tunnel 9→10). Audit portillia settings/config for ECH remnants before Phase 3.

`/v1/sign` shape (signer.go:77-110):
- POST only (`Allow` header on 405); `Content-Type: application/json` enforced;
- body `TranscriptSignRequest` (fields incl. `Binding`, `ClientHello` — see `signrpc` package / `types/api.go` for JSON tags);
- errors mapped: invalid argument→400, permission denied→403, other→500; success = JSON-encoded sign response.
- Current portillia handler (`keyless/server.c:189`) only verifies `X-Portal-Access-Token`; must additionally derive leaseID from the verified token claims and run `ValidateAndConsume`.

## 3. Routed HTTP semantics delta (portal-tunnel f567100b)

Reference: `sdk/http.go`. **Status: implemented (Phase 4)** in
`src/sdk/http_runtime.c` (`handle_client`, the C port of `sdk/http.go`; the relay's
`src/portal/proxy.c` is a byte-level bridge and has no HTTP semantics by design).
- **Host preservation**: outbound request Host = inbound browser Host — the C proxy
  forwards the browser's `Host` header untouched and never rewrites it to the
  loopback upstream (`pr.Out.Host = pr.In.Host`, :324). Before Phase 4 this already
  held de facto; it is now explicit and documented in code.
- **X-Forwarded-Proto**: any client-sent value is dropped and `X-Forwarded-Proto:
  https` is sent upstream unconditionally (:49) — the tunnel ends TLS for the
  public hostname. Before Phase 4 the header passed through unchanged (a
  client-sent `http` leaked to the upstream).
- Redirect rewriting (:328-415): **deferred** — the C runtime does not rewrite
  `Location` today.
- `X-Forwarded-For` append (`SetXForwarded`): **deferred** — not required by the
  parity checklist.

## 4. Phased implementation plan

### Phase 1 — cwist v3.8 + build fixes (Effort: M)
- Files: cwist submodule pin, `Makefile`/`CMake` link lines, `src/portal/transport/quic_backhaul.c` (delete local `cwist_yamux_*` stubs :20-53 once v3.8 helpers link).
- Deps: cwist v3.8 release (tracked separately).
- Outcome: clean build, no stub yamux.

### Phase 2 — Reverse-session framing + keyless bindings (Effort: L)
- New: `src/portal/keyless/bindings.c`, `include/portillia/portal/keyless/bindings.h` — C port of `bindings.go` (Issue/FixHello/ValidateAndConsume/Discard/SweepExpired, ClientHello accumulator). Hash table + mutex; single-owner of binding policy per portillia AGENTS.md.
- Touch: `src/portal/api_server.c` (`handle_connect` :474, reverse-session registry) — add `Claim`-equivalent that mints via bindings registry and writes `0x02 || binding` activation frame; keepalive `0x00`; raw `0x01` unchanged.
- Deps: Phase 1. Envelope field check vs `types/api.go:114-171`.
- Test: frame bytes match `stream_client.go:48-53` parse; binding mint/fix/consume unit tests mirroring `bindings_test.go`.

### Phase 3 — Tenant TLS termination support + `/v1/sign` (Effort: L)
- Touch: `src/portal/keyless/server.c` — replace body of `handle_keyless_sign` (:189) with `TranscriptSignRequest` decode + leaseID-from-token + `ValidateAndConsume` + sign; match error mapping in §2. Identity loading (:316-326) stays.
- Touch: settings/config — remove ECH remnants if found.
- Deps: Phase 2 registry; interop with Go SDK's `t13server` (portal-tunnel `e2e/` as oracle).
- Note: portillia implements signer side only; tenant termination lives in the Go SDK — validate against a real portal-tunnel SDK client.

### Phase 4 — Routed HTTP + version bump (Effort: M, bump S) — DONE
- `src/sdk/http_runtime.c` — Host preservation (forwarded untouched), `X-Forwarded-Proto: https` replacing client-sent values.
- Announce version rejection in `src/portal/api_server_relay.c` (mirrors `api_server.go:243-245`); responses derive from `PORTILLIA_DISCOVERY_VERSION`.
- Versions bumped: tunnel `10`, discovery `9` (`src/types/types.c` defaults + `config.toml [protocol]` overrides). All announce/domain/discovery sites use the constants.
- Envelope audit: see §6. WG fields kept (live overlay, see v9 checklist).
- Not done (deferred): datagram relay, redirect rewriting, C SDK t13server client-side validation against a live Go relay.
- Outcome: `make build-tunnel build-server build-demo` green; relay-server boots to `relay server started` (port 443/ACME failures in dev are environmental, pre-existing).

## 5. Behavior parity test checklist

Implemented in Phases 1-4 (code complete; runtime interop against a real Go SDK
client still pending for the items noted):
- [x] Reverse session: relay activation frame is exactly `0x02 || 16-byte binding`; Go SDK `stream_client.go` accepts and splits TLS vs raw.
- [x] Keepalive `0x00` bytes do not corrupt the stream (`stream_relay.go:439`).
- [x] Binding single-use: second `/v1/sign` with same binding → 403/400; unknown, expired, wrong-lease, wrong-hello all rejected (`bindings.go:69-96` cases).
- [x] Binding fixed exactly once; second `FixHello` rejected; `FixHelloOnWrite` accumulator handles fragmented/multi-record ClientHello up to 128 KiB.
- [x] Undelivered bindings discarded; expired entries swept.
- [x] `/v1/sign`: 405 on non-POST, 415 on bad content type, 400 on bad JSON, 403 on lease/binding mismatch, 500 otherwise; success returns valid transcript signature consumable by SDK t13server (end-to-end TLS 1.3 handshake through the relay).
- [ ] MITM negative case: ClientHello altered in transit → helloHash mismatch → sign rejected (cf. portal-tunnel `e2e/mitm_test.go`). Needs a live Go SDK client run.
- [x] Announce: relay rejects mismatched `protocol_version` like `api_server.go:243-245` (`src/portal/api_server_relay.c`, 400 `invalid_request` with `announce protocol mismatch` message). C SDK domain check (`sdk/api_client.go:73-76` equivalent) already existed at `src/sdk/api_client.c:871`.
- [x] Routed HTTP: loopback upstream receives browser Host header; `X-Forwarded-Proto` always `https` regardless of client-sent value (`src/sdk/http_runtime.c`).
- [ ] Rolling upgrade: v10 relay + v9 client cleanly rejected with version-mismatch error (no half-open sessions). Needs two live versions.
- [x] Versions: tunnel `10` / discovery `9` at `src/types/types.c:380-381` (defaults) and `config.toml [protocol]` (runtime override loaded by `portillia_manifest_init`); all announce/domain/discovery responses derive from `PORTILLIA_SDK_VERSION` / `PORTILLIA_DISCOVERY_VERSION` (no hardcoded leftovers).

## 6. Envelope audit (Phase 4) — field-by-field vs `types/api.go:114-171`

Fixed:
- `DiscoveryResponse` was missing `release_version` → added
  (`src/portal/api_server.c` `handle_discovery`).
- `DiscoveryAnnounceResponse.protocol_version` was hardcoded `"7"` in
  `api_server_relay.c` → now `PORTILLIA_DISCOVERY_VERSION`; announce-request
  version rejection added (mirrors `api_server.go:243-245`).

Accepted drift (justified):
- `RelayDescriptor` carries extra portillia fields (`wireguard_*`, `overlay_*`,
  `load*`, `sequence`, ...) — superset of the reference (incl. `ivnp_destination`,
  which belongs to the reference's IVNP overlay that portillia does not implement).
  Extra JSON fields are ignored by Go. Signing and verification now both use the
  Go canonical form (`canonicalRelayDescriptorBytes`): `VerifyDescriptorJSON`
  tries the Go form first (legacy portillia long/short forms remain as
  fallbacks), and portillia's own announce is signed through
  `SignDescriptorJSON`, so descriptors verify in both directions.
- `IncompatibleRelayEntry` / `RelayReleaseVersions` on `DiscoveryResponse` not
  ported (rolling-upgrade visibility metadata; portillia's relay set already drops
  version-mismatched relays at `src/portal/discovery/relay_set.c:455`).

## 7. Interop hardening (2026-10-01)

- **BoringSSL-only link.** Portillia sources compile against the vendored
  BoringSSL headers and the final link no longer pulls system `-lssl/-lcrypto`,
  so no OpenSSL-3-only symbol can interpose into cwist's TLS stack at runtime
  (`nm -D bin/relay-server | grep OPENSSL_3` → empty). The keyless remote RSA
  signer uses the BoringSSL `ENGINE`/`RSA_METHOD` API.
- **`reverse_endpoint`.** `/sdk/register` and `/sdk/renew` return
  `reverse_endpoint {url, capability, expires_at}` (portal-tunnel
  `types/api.go:99`). The capability is the lease token; `/sdk/connect` admits
  it via `X-Portal-Reverse-Capability`.
- **cwist worker model.** cwist preforks one worker per core (SO_REUSEPORT).
  The register challenge store lives in `MAP_SHARED` anonymous memory with a
  process-shared mutex, so challenge+register survive landing on different
  workers. The tunnel data path cannot: it splices kernel fds and `SSL*`
  handles between the reverse session and the SNI listener, which must live in
  one process. The relay therefore defaults to `CWIST_WORKERS=1`
  (`cmd/relay-server/main.c`; explicit env overrides). Cross-worker fd passing
  (SCM_RIGHTS to a splice owner) is the known follow-up if multi-worker data
  path is ever needed.

## 8. Still unimplemented (tracked, out of Phase 4 scope)

- C SDK tenant-TLS transcript signing port: `/v1/sign` relay side is done, but the
  C SDK does not yet drive the full `t13server`-style tenant termination against a
  live Go relay; validated only against portillia's own signer.
- Datagram (UDP) relay (`datagram_*.go`) — no C counterpart.
- Routed HTTP redirect `Location` rewriting and `X-Forwarded-For` append.
- QUIC backhaul remains a local yamux pump over lsquic, not the reference's
  production flow-controlled stack.
