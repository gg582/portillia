package overlay

import (
	"testing"

	"github.com/gosuda/portal-tunnel/v2/portal/policy"
)

func TestReverseSiameseComplementMirror(t *testing.T) {
	magic := buildMagicOrthogonalLatinGrid(3, 5)
	reverse := deriveReverseSiameseGrid(magic)
	complementConst := uint16(len(magic) + 1)

	row, col := 17, 9
	mirroredCol := molsSize - 1 - col
	got := reverse[row*molsSize+col]
	want := complementConst - magic[row*molsSize+mirroredCol]
	if got != want {
		t.Fatalf("reverse-siamese mismatch: got %d want %d", got, want)
	}
}

func TestBuildRouteSwitchesOnCongestion(t *testing.T) {
	p := NewRoutePolicy()
	candidates := []uint32{101, 102, 103, 104, 105}

	normal, err := p.BuildRouteWithLoad(42, candidates, 3, policy.NodeLoad{AvgLatencyMs: 20}, 100)
	if err != nil {
		t.Fatalf("normal route error: %v", err)
	}
	congested, err := p.BuildRouteWithLoad(42, candidates, 3, policy.NodeLoad{AvgLatencyMs: 180}, 100)
	if err != nil {
		t.Fatalf("congested route error: %v", err)
	}

	if len(normal) != 4 || len(congested) != 4 {
		t.Fatalf("unexpected route length normal=%d congested=%d", len(normal), len(congested))
	}

	if normal[0] != 42 || congested[0] != 42 {
		t.Fatalf("ingress must be first hop")
	}

	same := true
	for i := range normal {
		if normal[i] != congested[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("expected congestion route switch, got same route: %v", normal)
	}
}

func TestBuildRouteRejectsEmptyCandidates(t *testing.T) {
	p := NewRoutePolicy()
	_, err := p.BuildRoute(1, nil, 1, false)
	if err == nil {
		t.Fatal("expected error for empty candidates")
	}
}

func TestMagicOrthogonalLatinGridIsMagicSquare(t *testing.T) {
	magic := buildMagicOrthogonalLatinGrid(3, 5)
	if !isMagicSquare(magic) {
		t.Fatal("grid lost magic square invariants")
	}
}
