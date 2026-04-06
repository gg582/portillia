package overlay

import (
	"errors"
	"sort"

	"github.com/gosuda/portal/v2/portal/policy"
)

const (
	molsFieldDegree   = 6
	molsSize          = 1 << molsFieldDegree // order-64 MOLS grid
	molsMask          = molsSize - 1
	molsPrimitivePoly = 0b1000011 // x^6 + x + 1
)

// RoutePolicy selects overlay relay hops using an order-64 MOLS-derived magic
// square. During congestion it switches to the reverse-Siamese complement grid
// (original policy), i.e. B(i,j)=c-A(i,n+1-j).
type RoutePolicy struct {
	magic   []uint16
	reverse []uint16
}

func NewRoutePolicy() *RoutePolicy {
	magic := buildMagicOrthogonalLatinGrid(3, 5)
	reverse := deriveReverseSiameseGrid(magic)
	return &RoutePolicy{magic: magic, reverse: reverse}
}

// BuildRoute returns [ingress, hop1, hop2, ...]. maxHops is the number of
// relays after ingress and is clamped to [1, len(candidates)].
func (p *RoutePolicy) BuildRoute(ingress uint32, candidates []uint32, maxHops int, congested bool) ([]uint32, error) {
	if len(candidates) == 0 {
		return nil, errors.New("candidates empty")
	}
	if maxHops <= 0 {
		maxHops = 1
	}
	if maxHops > len(candidates) {
		maxHops = len(candidates)
	}

	grid := p.magic
	if congested {
		grid = p.reverse
	}

	row := int(ingress & molsMask)
	scores := make([]scoredNode, 0, len(candidates))
	for _, nodeID := range candidates {
		col := int(nodeID & molsMask)
		score := grid[row*molsSize+col]
		scores = append(scores, scoredNode{nodeID: nodeID, score: score})
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].score == scores[j].score {
			return scores[i].nodeID < scores[j].nodeID
		}
		return scores[i].score < scores[j].score
	})

	route := make([]uint32, 0, maxHops+1)
	route = append(route, ingress)
	for i := 0; i < maxHops; i++ {
		route = append(route, scores[i].nodeID)
	}
	return route, nil
}

// BuildRouteWithLoad applies the original reverse-Siamese congestion trigger:
// switch to reverse grid when average latency exceeds threshold.
func (p *RoutePolicy) BuildRouteWithLoad(ingress uint32, candidates []uint32, maxHops int, load policy.NodeLoad, congestionLatencyMs float64) ([]uint32, error) {
	congested := load.AvgLatencyMs >= congestionLatencyMs
	return p.BuildRoute(ingress, candidates, maxHops, congested)
}

type scoredNode struct {
	nodeID uint32
	score  uint16
}

func gfMul(a, b uint8) uint8 {
	res := uint8(0)
	for b != 0 {
		if b&1 == 1 {
			res ^= a
		}
		b >>= 1
		a <<= 1
		if a&uint8(molsSize) != 0 {
			a ^= molsPrimitivePoly
		}
		a &= uint8(molsMask)
	}
	return res & uint8(molsMask)
}

func buildGFLatin(multiplier uint8) []uint8 {
	square := make([]uint8, molsSize*molsSize)
	for i := 0; i < molsSize; i++ {
		for j := 0; j < molsSize; j++ {
			square[i*molsSize+j] = uint8(i) ^ gfMul(multiplier, uint8(j))
		}
	}
	return square
}

func buildMagicOrthogonalLatinGrid(multiplierA, multiplierB uint8) []uint16 {
	latinA := buildGFLatin(multiplierA)
	latinB := buildGFLatin(multiplierB)
	grid := make([]uint16, molsSize*molsSize)
	for i := range grid {
		grid[i] = uint16(latinA[i])*molsSize + uint16(latinB[i]) + 1
	}
	return grid
}

func deriveReverseSiameseGrid(square []uint16) []uint16 {
	out := make([]uint16, len(square))
	complementConst := uint16(len(square) + 1)
	for row := 0; row < molsSize; row++ {
		for col := 0; col < molsSize; col++ {
			src := row*molsSize + (molsSize - 1 - col)
			out[row*molsSize+col] = complementConst - square[src]
		}
	}
	return out
}
