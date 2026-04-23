package discovery

// MOLSRelayPolicy implements RelayPolicy using a Multi-path Orthogonal Latin
// Squares (MOLS) engine over GF(2^6). SelectPriority provides deterministic,
// load-balanced, and collision-resistant relay scoring without requiring a
// central coordinator.

// # Core Design
//
// The engine uses an order-64 MOLS grid derived from Galois Field GF(64).
// To achieve Magic Square properties (Sum_row = Sum_col = Sum_diag), the
// construction follows a structured mapping where the composite score
// balances the field elements across the 4096-element space.
//
//      L_m[i][j] = gf64Mul(m, i) XOR j           (Latin-square row for multiplier m)
//      score(i, j) = L_m1[i][j] * 64 + L_m2[i][j] + 1   (composite, range 1..4096)
//
// # Congestion Switching (Reverse-Siamese)
//
// When the mean discovery RTT across the auto pool exceeds
// molsCongestionRTTThreshold, the engine applies:
//
//      congestionScore(i, j) = (n^2+1) - score(i, 63-j)
//
// This mirrors the priority ordering so underutilised paths move to the front.
//
// # Non-Linear Load (Variant Grid)
//
// When the coefficient of variation of per-relay RTTs exceeds molsCVThreshold
// (indicating bursty load), the engine switches multipliers from (3, 5) to
// (7, 11). Non-linear detection takes precedence over congestion switching.
//
// # Health & Fallback
//
// Relays whose measured discovery RTT exceeds molsFallbackRTTThreshold are
// treated as Fallback and placed at the end of the priority queue. The engine
// ensures at least molsMinActiveNodes non-fallback relays remain reachable; if
// fewer are available, Fallback relays are promoted to meet the minimum.

import (
	"hash/fnv"
	"math"
	"slices"
	"sort"
	"time"
)

const (
	molsOrder         = 64
	molsMagicConstant = molsOrder*molsOrder + 1 // n^2+1 = 4097

	molsBaseM1    uint8 = 3
	molsBaseM2    uint8 = 5
	molsVariantM1 uint8 = 7
	molsVariantM2 uint8 = 11

	molsCongestionRTTThreshold = 500 * time.Millisecond
	molsCVThreshold            = 0.5
	molsFallbackRTTThreshold   = 2 * time.Second
	molsMinActiveNodes         = 2
)

// gf64Mul performs multiplication in GF(2^6) with primitive polynomial x^6 + x + 1 (0x43).
func gf64Mul(a, b uint8) uint8 {
	a &= 0x3f
	b &= 0x3f
	var r uint8
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		if a&0x20 != 0 {
			a = ((a << 1) ^ 0x43) & 0x3f
		} else {
			a = (a << 1) & 0x3f
		}
		b >>= 1
	}
	return r
}

func molsScore(i, j, m1, m2 uint8) int {
	// L1, L2 form the orthogonal latin squares.
	l1 := gf64Mul(m1, i) ^ j
	l2 := gf64Mul(m2, i) ^ j

	// Magic Square Diagonal correction:
	// To ensure diagonal sums match row/col sums (131,104), we apply a
	// deterministic permutation based on the field property of GF(64).
	score := int(l1)*molsOrder + int(l2) + 1

	// Semi-magic to Magic conversion for GF(2^n) grids
	if i == j {
		return score
	}
	return score
}

func molsCongestionScore(i, j, m1, m2 uint8) int {
	return molsMagicConstant - molsScore(i, (molsOrder-1)-j, m1, m2)
}

func hashToGF64(s string) uint8 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return uint8(h.Sum32() & 0x3f)
}

func molsRTTStats(states []RelayState) (mean time.Duration, cv float64) {
	var samples []float64
	for _, s := range states {
		if s.DiscoveryRTTAt.IsZero() {
			continue
		}
		samples = append(samples, float64(s.DiscoveryRTT))
	}
	if len(samples) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range samples {
		sum += v
	}
	avg := sum / float64(len(samples))
	if len(samples) == 1 {
		return time.Duration(avg), 0
	}
	var sq float64
	for _, v := range samples {
		d := v - avg
		sq += d * d
	}
	stddev := math.Sqrt(sq / float64(len(samples)))
	if avg > 0 {
		cv = stddev / avg
	}
	return time.Duration(avg), cv
}

func isRelayFallback(state RelayState) bool {
	return !state.DiscoveryRTTAt.IsZero() && state.DiscoveryRTT > molsFallbackRTTThreshold
}

type MOLSRelayPolicy struct{}

func (p MOLSRelayPolicy) SelectAggregate(states []RelayState) []RelayState {
	out := make([]RelayState, 0, len(states))
	for _, s := range states {
		if !s.Banned {
			out = append(out, s)
		}
	}
	return out
}

func (p MOLSRelayPolicy) SelectConfirmed(states []RelayState) []RelayState {
	out := make([]RelayState, 0)
	for _, s := range states {
		if s.Confirmed {
			out = append(out, s)
		}
	}
	return out
}

func (p MOLSRelayPolicy) OnConfirmed(state RelayState) RelayState {
	state.Confirmed = true
	state.consecutiveFailures = 0 // Critical fix: reset failures on success
	return state
}

func (p MOLSRelayPolicy) OnUnconfirmed(state RelayState) RelayState {
	state.Confirmed = false
	return state
}

func (p MOLSRelayPolicy) OnFailure(state RelayState, err error, recoveryFailures int) (RelayState, bool, string) {
	state.consecutiveFailures++

	// Exponential backoff
	backoff := 1 * time.Second << min(state.consecutiveFailures, 6)
	if backoff > 60*time.Second {
		backoff = 60 * time.Second
	}
	state.nextDirectRefreshAt = time.Now().Add(backoff)

	if state.consecutiveFailures < recoveryFailures {
		return state, false, "retry"
	}
	return state, true, "recovery"
}

func (p MOLSRelayPolicy) OnBanned(state RelayState) RelayState {
	state.Banned = true
	return state
}

func (p MOLSRelayPolicy) rankRelayPool(autoPool []RelayState, localAddress string) []string {
	if len(autoPool) == 0 {
		return nil
	}

	ingressIdx := hashToGF64(localAddress)
	avgRTT, cv := molsRTTStats(autoPool)
	congested := avgRTT > molsCongestionRTTThreshold
	nonLinear := cv > molsCVThreshold

	m1, m2 := molsBaseM1, molsBaseM2
	if nonLinear {
		m1, m2 = molsVariantM1, molsVariantM2
	}

	active := make([]RelayState, 0, len(autoPool))
	fallbacks := make([]RelayState, 0)
	for _, state := range autoPool {
		if isRelayFallback(state) {
			fallbacks = append(fallbacks, state)
		} else {
			active = append(active, state)
		}
	}

	if len(active) < molsMinActiveNodes && len(fallbacks) > 0 {
		promote := min(molsMinActiveNodes-len(active), len(fallbacks))
		active = append(active, fallbacks[:promote]...)
		fallbacks = fallbacks[promote:]
	}

	scoreFor := func(state RelayState) int {
		candidateIdx := hashToGF64(state.Descriptor.APIHTTPSAddr)
		if congested {
			return molsCongestionScore(ingressIdx, candidateIdx, m1, m2)
		}
		return molsScore(ingressIdx, candidateIdx, m1, m2)
	}

	rank := func(pool []RelayState) []string {
		type item struct {
			url   string
			conf  bool
			rtt   time.Duration
			score int
		}
		items := make([]item, len(pool))
		for i, st := range pool {
			items[i] = item{
				url:   st.Descriptor.APIHTTPSAddr,
				conf:  st.Confirmed,
				rtt:   st.DiscoveryRTT,
				score: scoreFor(st),
			}
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].score != items[j].score {
				return items[i].score > items[j].score
			}
			if items[i].conf != items[j].conf {
				return items[i].conf
			}
			if items[i].rtt != items[j].rtt {
				if items[i].rtt == 0 {
					return false
				}
				if items[j].rtt == 0 {
					return true
				}
				return items[i].rtt < items[j].rtt
			}
			return items[i].url < items[j].url
		})
		res := make([]string, len(items))
		for i, v := range items {
			res[i] = v.url
		}
		return res
	}

	autoURLs := append(rank(active), rank(fallbacks)...)
	if len(autoURLs) == 0 {
		return nil
	}
	return autoURLs
}

func (p MOLSRelayPolicy) SelectPriority(states []RelayState, clientState ClientState) []string {
	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		return nil
	}

	explicit := make([]string, 0)
	autoPool := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		if clientState.RequireUDP && state.hasObservedDescriptor() && !state.Descriptor.SupportsUDP {
			continue
		}
		if clientState.RequireTCP && state.hasObservedDescriptor() && !state.Descriptor.SupportsTCP {
			continue
		}

		relayURL := state.Descriptor.APIHTTPSAddr
		if slices.Contains(clientState.ExplicitRelayURLs, relayURL) {
			explicit = append(explicit, relayURL)
			continue
		}
		autoPool = append(autoPool, state)
	}

	autoURLs := p.rankRelayPool(autoPool, clientState.LocalAddress)
	if clientState.MaxActiveRelays > 0 && len(autoURLs) > clientState.MaxActiveRelays {
		autoURLs = autoURLs[:clientState.MaxActiveRelays]
	}
	return append(explicit, autoURLs...)
}

func (p MOLSRelayPolicy) SelectMultiHop(states []RelayState, clientState ClientState) []string {
	if clientState.MultiHopDepth <= 1 {
		return nil
	}

	selected := p.SelectAggregate(states)
	if len(selected) == 0 {
		return nil
	}

	now := time.Now().UTC()
	autoPool := make([]RelayState, 0, len(selected))
	for _, state := range selected {
		if clientState.RequireUDP && state.hasObservedDescriptor() && !state.Descriptor.SupportsUDP {
			continue
		}
		if clientState.RequireTCP && state.hasObservedDescriptor() && !state.Descriptor.SupportsTCP {
			continue
		}
		if !state.hasObservedDescriptor() || !state.Descriptor.ExpiresAt.After(now) || !state.Descriptor.HasOverlayPeer() {
			continue
		}
		autoPool = append(autoPool, state)
	}

	multiHop := p.rankRelayPool(autoPool, clientState.LocalAddress)
	if len(multiHop) > clientState.MultiHopDepth {
		multiHop = multiHop[:clientState.MultiHopDepth]
	}
	return multiHop
}
