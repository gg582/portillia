# OLS Branch Change Log

## Delta vs `origin/main`

- Introduced a Tor-style onion encapsulation engine (`portal/overlay/onion.go`) plus deterministic unit tests so every hop only learns its downstream neighbor and TTL budget.
- Guarded the order-64 orthogonal Latin square grid with a runtime magic-square validator and regression coverage to ensure the Siamese complement pair cannot silently degrade.
- Added a runnable simulation harness (`cmd/onion-sim`, `scripts/run_onion_sim.sh`) that spins up N virtual relays with pseudo public IPs, exercises onion routing end-to-end, and emits hop-by-hop traces for reviewers. The harness now includes a `steady → churn → recover` state machine so reviewers can model long-lived deployments with periodic route churn.

## Purpose / Behavior

- Make the overlay transport self-contained: we now mint hop keys via HKDF, wrap the payload with ChaCha20-Poly1305 layers, and reject malformed onions before they enter the routing plane.
- Preserve the determinism guarantees of the existing OLS-based policy; if the grid ever stops being a Latin magic square we panic immediately instead of letting skew leak into production routes.
- Provide an operator-facing verification workflow so reviewers can replay the exact route (ingress + hops) without touching tenant code or real relays, including simulations of long-running churn cycles.

## Anonymity Considerations

- Each hop decrypts exactly one layer: it sees its own symmetric key, the remaining TTL, and either (a) the numeric ID of the next hop or (b) zero to terminate locally. No hop can infer the full circuit because previous/next identifiers are never co-located.
- Integrity failures (tampering with ciphertext, nonce replays, TTL underflow) abort immediately and never leak partial plaintext, mirroring Tor’s fail-fast semantics.
- The simulator randomizes relay IDs and uses the documentation prefix block `198.51.100.0/24`, making it clear in logs which fields are safe to expose. Churn epochs highlight which relays entered or left the path so reviewers can reason about anonymity set evolution over time.

## Performance Expectations

- Hop construction is O(n) with fixed-size ChaCha20-Poly1305 operations; the additional runtime check for the Latin grid is performed once at policy initialization and uses integer additions only.
- The simulator runs entirely in-process (no Docker or kernel namespaces), so it completes in sub-second time even with 10+ hops and dozens of epochs. The state machine reuses the same production code paths, adding only lightweight slice copies and shuffles.

## Implementation Walkthrough / Review Order

1. **`portal/overlay/onion.go`** — Core builder and peeling helpers. Review HKDF label usage, TTL enforcement, and `nextHop` encoding (0 indicates sink).
2. **`portal/overlay/onion_test.go`** — Regression coverage for round-trip routing, TTL exhaustion, and ciphertext tampering; mirrors the builder logic for future reviewers.
3. **`portal/overlay/routing_policy.go`** — `ensureMagicSquare` guard plus `isMagicSquare` helper. Focus on the uniqueness checks and diagonal sums; panic path is intentional to surface invalid configuration early.
4. **`portal/overlay/routing_policy_test.go`** — Adds a single invariant test so reviewers can diff expected sums while scanning policy changes.
5. **`cmd/onion-sim` + `scripts/run_onion_sim.sh`** — CLI harness that provisions virtual relays, derives hop keys, pushes an onion across concurrent goroutines, and logs each hop’s TTL + downstream target so reviewers can “watch” the route. Use the new `--epochs`, `--churn-every`, `--churn-span`, and `--state-seed` flags to simulate route churn in long-lived deployments.

## Test Plan

1. **Unit + lint**  
   ```bash
   go test ./...
   $(go env GOPATH)/bin/golangci-lint run ./cmd/... ./portal/... ./sdk/... ./types/...
   ```
   Ensures deterministic onion math and OLS invariants stay safe.
2. **Deterministic onion simulation**  
   ```bash
   ./scripts/run_onion_sim.sh --relays 6 --hops 4 --payload "l7-health-check" --ttl 12 --epochs 5 --churn-every 2
   ```
   - Creates six virtual relays, builds four-hop onions across multiple epochs, and prints log lines such as  
     `"[epoch 02 state=churn hop=relay-tyo-exit 198.51.100.14] ttl=10 -> next hop relay-gru-core(198.51.100.18)"`.
   - Final log per epoch must read `terminal decrypted payload` and the program must exit cleanly; any mismatch or timeout fails with a descriptive error.
3. **(Optional) Custom route replay**  
   Supply `--relays N --hops M --epochs E --payload "...json..."` to mirror production-sized circuits; useful when reviewing policy tweaks or evaluating anonymity budgets.

Full instructions (including failure forensics and state-machine tuning) live in `docs/onion_testing.md`.
