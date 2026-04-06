package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"os"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
)

type simRelay struct {
	ID       uint32
	Name     string
	PublicIP string
}

type hopResult struct {
	Relay        simRelay
	NextHop      uint32
	TTL          uint8
	InnerPayload []byte
	Error        error
}

var shuffleRNG = mrand.New(mrand.NewSource(time.Now().UnixNano()))

func main() {
	var (
		relayCount = flag.Int("relays", 5, "total relays in the simulated overlay (ingress + hops)")
		hopCount   = flag.Int("hops", 3, "number of onion hops after the ingress")
		baseTTL    = flag.Int("ttl", 12, "initial TTL budget for the onion")
		payloadStr = flag.String("payload", "ols-l7-routing", "payload to deliver through the onion")
		label      = flag.String("label", "ols-regression", "HKDF label used for hop key derivation")
		timeout    = flag.Duration("timeout", 10*time.Second, "overall simulation timeout per epoch")
		epochs     = flag.Int("epochs", 1, "number of epochs (routing windows) to simulate")
		churnEvery = flag.Int("churn-every", 5, "force a churn state every N epochs (0 disables churn)")
		churnSpan  = flag.Int("churn-span", 0, "minimum number of relays swapped during churn (0 = auto)")
		stateSeed  = flag.Int64("state-seed", time.Now().UnixNano(), "deterministic seed for state-machine shuffles")
	)
	flag.Parse()

	if *relayCount < 2 {
		log.Fatal("relay count must be at least 2 (ingress + one hop)")
	}
	if *hopCount <= 0 {
		log.Fatal("hops must be at least 1")
	}
	if *hopCount >= *relayCount {
		log.Fatalf("hops (%d) must be less than total relays (%d)", *hopCount, *relayCount)
	}
	if *baseTTL < *hopCount {
		log.Fatalf("ttl (%d) must be >= hop count (%d)", *baseTTL, *hopCount)
	}
	if *epochs <= 0 {
		log.Fatal("epochs must be >= 1")
	}
	if *churnEvery < 0 {
		log.Fatal("churn-every must be >= 0")
	}

	relays := provisionRelays(*relayCount)
	if *churnSpan <= 0 {
		*churnSpan = max(1, *hopCount/3)
	}

	stateMachine := newRouteStateMachine(relays, *churnEvery, *churnSpan, *stateSeed)
	var previousRoute map[uint32]struct{}

	for epoch := 1; epoch <= *epochs; epoch++ {
		state, route := stateMachine.planRoute(epoch, *hopCount)
		added, removed := diffRoute(previousRoute, route)
		log.Printf("\n[epoch %02d state=%s] ingress %s -> hops %d, payload=%q, ttl=%d (Δ +%d / -%d nodes)",
			epoch, state, describeRelay(route[0]), len(route)-1, *payloadStr, *baseTTL, len(added), len(removed))
		for idx, r := range route[1:] {
			nextDesc := "terminate"
			if idx+2 < len(route) {
				nextDesc = describeRelay(route[idx+2])
			}
			log.Printf("  hop %d -> %s forwards to %s", idx+1, describeRelay(r), nextDesc)
		}
		if err := simulateEpoch(route, []byte(*payloadStr), uint8(*baseTTL), fmt.Sprintf("%s/epoch-%d/%s", *label, epoch, state), *timeout, epoch, state); err != nil {
			log.Fatalf("epoch %d failed: %v", epoch, err)
		}
		log.Println("[epoch", epoch, "] simulation complete: onion route delivered payload intact.")
		previousRoute = routeSet(route)
	}
}

func provisionRelays(count int) []simRelay {
	names := []string{"nyc-edge", "lon-core", "fra-core", "sin-exit", "tyo-exit", "sfo-core", "dal-edge", "ams-exit", "gru-core", "syd-exit"}
	relays := make([]simRelay, count)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("relay-%s", names[i%len(names)])
		ip := fmt.Sprintf("198.51.100.%d", 10+i)
		relays[i] = simRelay{
			ID:       randomNodeID(),
			Name:     name,
			PublicIP: ip,
		}
	}
	shuffle(relays)
	return relays
}

func randomNodeID() uint32 {
	buf := make([]byte, 4)
	if _, err := crand.Read(buf); err != nil {
		panic(err)
	}
	return uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
}

func shuffle(relays []simRelay) {
	shuffleRNG.Shuffle(len(relays), func(i, j int) {
		relays[i], relays[j] = relays[j], relays[i]
	})
}

func describeRelay(r simRelay) string {
	return fmt.Sprintf("%s(%s)", r.Name, r.PublicIP)
}

func describeByID(route []simRelay, id uint32) string {
	for _, r := range route {
		if r.ID == id {
			return describeRelay(r)
		}
	}
	return fmt.Sprintf("unknown(%d)", id)
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
}

type epochState string

const (
	stateSteady  epochState = "steady"
	stateChurn   epochState = "churn"
	stateRecover epochState = "recover"
)

type routeStateMachine struct {
	base       []simRelay
	churnEvery int
	churnSpan  int
	rng        *mrand.Rand
	lastState  epochState
}

func newRouteStateMachine(relays []simRelay, churnEvery, churnSpan int, seed int64) *routeStateMachine {
	if churnEvery == 0 {
		churnSpan = 0
	}
	return &routeStateMachine{
		base:       append([]simRelay(nil), relays...),
		churnEvery: churnEvery,
		churnSpan:  churnSpan,
		rng:        mrand.New(mrand.NewSource(seed)),
		lastState:  stateSteady,
	}
}

func (sm *routeStateMachine) planRoute(epoch, hops int) (epochState, []simRelay) {
	state := stateSteady
	if sm.churnEvery > 0 && epoch%sm.churnEvery == 0 {
		state = stateChurn
	} else if sm.lastState == stateChurn {
		state = stateRecover
	}
	sm.lastState = state

	switch state {
	case stateChurn:
		return state, sm.churnRoute(hops)
	case stateRecover:
		return state, sm.recoverRoute(epoch, hops)
	default:
		return state, sliceCopy(sm.base[:hops+1])
	}
}

func (sm *routeStateMachine) churnRoute(hops int) []simRelay {
	pool := sliceCopy(sm.base)
	sm.rng.Shuffle(len(pool), func(i, j int) {
		pool[i], pool[j] = pool[j], pool[i]
	})
	if sm.churnSpan > 0 && sm.churnSpan < len(pool) {
		offset := sm.rng.Intn(len(pool)-sm.churnSpan) + sm.churnSpan
		pool = append(pool[offset:], pool[:offset]...)
	}
	return sliceCopy(pool[:hops+1])
}

func (sm *routeStateMachine) recoverRoute(epoch, hops int) []simRelay {
	rot := epoch % len(sm.base)
	out := make([]simRelay, 0, hops+1)
	for i := 0; i < hops+1; i++ {
		out = append(out, sm.base[(rot+i)%len(sm.base)])
	}
	return out
}

func sliceCopy(src []simRelay) []simRelay {
	dst := make([]simRelay, len(src))
	copy(dst, src)
	return dst
}

func routeSet(route []simRelay) map[uint32]struct{} {
	if len(route) == 0 {
		return nil
	}
	set := make(map[uint32]struct{}, len(route))
	for _, r := range route {
		set[r.ID] = struct{}{}
	}
	return set
}

func diffRoute(previous map[uint32]struct{}, route []simRelay) (added, removed []uint32) {
	if previous == nil {
		return routeIDs(route), nil
	}
	current := routeSet(route)
	for id := range current {
		if _, ok := previous[id]; !ok {
			added = append(added, id)
		}
	}
	for id := range previous {
		if _, ok := current[id]; !ok {
			removed = append(removed, id)
		}
	}
	return
}

func routeIDs(route []simRelay) []uint32 {
	out := make([]uint32, len(route))
	for i, r := range route {
		out[i] = r.ID
	}
	return out
}

func simulateEpoch(route []simRelay, payload []byte, ttl uint8, label string, timeout time.Duration, epoch int, state epochState) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	keySeed := make([]byte, 32)
	if _, err := crand.Read(keySeed); err != nil {
		return fmt.Errorf("epoch %d seed: %w", epoch, err)
	}
	hopKeys, err := overlay.DeriveOnionKeys(keySeed, len(route)-1, label)
	if err != nil {
		return fmt.Errorf("epoch %d derive keys: %w", epoch, err)
	}
	routeIDs := routeIDs(route)
	onion, err := overlay.BuildOnionPayload(routeIDs, hopKeys, payload, ttl)
	if err != nil {
		return fmt.Errorf("epoch %d build onion: %w", epoch, err)
	}

	channels := make(map[uint32]chan []byte, len(route)-1)
	for _, hop := range route[1:] {
		channels[hop.ID] = make(chan []byte, 1)
	}

	resultCh := make(chan hopResult, len(route)-1)
	for hopIdx, relay := range route[1:] {
		expectedNext := uint32(0)
		if hopIdx+2 < len(route) {
			expectedNext = route[hopIdx+2].ID
		}
		inbound := channels[relay.ID]
		key := hopKeys[hopIdx]
		go func(relay simRelay, expectedNext uint32, inbound <-chan []byte, key []byte) {
			select {
			case <-ctx.Done():
				resultCh <- hopResult{Relay: relay, Error: ctx.Err()}
				return
			case msg := <-inbound:
				next, hopTTL, inner, err := overlay.PeelOnionLayer(key, msg)
				if err != nil {
					resultCh <- hopResult{Relay: relay, Error: err}
					return
				}
				if next != expectedNext {
					resultCh <- hopResult{Relay: relay, Error: fmt.Errorf("expected next hop %d, got %d", expectedNext, next)}
					return
				}
				resultCh <- hopResult{Relay: relay, NextHop: next, TTL: hopTTL, InnerPayload: inner}
				if next == 0 {
					return
				}
				nextCh, ok := channels[next]
				if !ok {
					resultCh <- hopResult{Relay: relay, Error: fmt.Errorf("no channel for hop %d", next)}
					return
				}
				nextCh <- inner
			}
		}(relay, expectedNext, inbound, key)
	}

	firstHopID := route[1].ID
	channels[firstHopID] <- onion

	var finalPayload []byte
	completed := 0
	for completed < len(route)-1 {
		select {
		case <-ctx.Done():
			return fmt.Errorf("epoch %d timeout: %w", epoch, ctx.Err())
		case res := <-resultCh:
			if res.Error != nil {
				return fmt.Errorf("epoch %d hop %s error: %w", epoch, describeRelay(res.Relay), res.Error)
			}
			if res.NextHop == 0 {
				finalPayload = res.InnerPayload
				log.Printf("[epoch %02d state=%s hop=%-12s %s] terminal decrypted payload (%d bytes)",
					epoch, state, res.Relay.Name, res.Relay.PublicIP, len(res.InnerPayload))
			} else {
				log.Printf("[epoch %02d state=%s hop=%-12s %s] ttl=%d -> next hop %s",
					epoch, state, res.Relay.Name, res.Relay.PublicIP, res.TTL, describeByID(route, res.NextHop))
			}
			completed++
		}
	}

	if !bytes.Equal(finalPayload, payload) {
		return fmt.Errorf("epoch %d payload mismatch: got %q want %q", epoch, string(finalPayload), string(payload))
	}
	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
