package graph

import (
	"testing"

	"github.com/TheManticoreProject/gopengraph/properties"
)

func TestEnsureNodeIsIdempotent(t *testing.T) {
	g := NewDedupedGraph(SourceKindBase)

	first := properties.NewProperties()
	first.SetProperty("name", "FIRST")
	if !g.EnsureNode("node-1", []string{NodeKindKeyCredential}, first) {
		t.Fatal("EnsureNode() = false on an empty graph, want true")
	}

	second := properties.NewProperties()
	second.SetProperty("name", "SECOND")
	if !g.EnsureNode("node-1", []string{NodeKindKeyCredential}, second) {
		t.Error("EnsureNode() = false for an id already in the graph, want true")
	}

	if count := g.OG.GetNodeCount(); count != 1 {
		t.Errorf("node count = %d, want 1", count)
	}
	if name := g.OG.GetNode("node-1").GetProperty("name"); name != "FIRST" {
		t.Errorf("name property = %v, want FIRST: the node already in the graph should be kept", name)
	}
}

func TestEnsureNodeRejectsEmptyID(t *testing.T) {
	g := NewDedupedGraph(SourceKindBase)

	if g.EnsureNode("", []string{NodeKindKeyCredential}, properties.NewProperties()) {
		t.Error("EnsureNode(\"\") = true, want false")
	}
	if count := g.OG.GetNodeCount(); count != 0 {
		t.Errorf("node count = %d, want 0", count)
	}
}

func TestAddEdgeRequiresBothEndpoints(t *testing.T) {
	g := NewDedupedGraph(SourceKindBase)
	g.EnsureNode("start", []string{NodeKindKeyCredential}, properties.NewProperties())

	if g.AddEdge("start", "missing", EdgeKindHasKeyMaterial, properties.NewProperties()) {
		t.Error("AddEdge() = true with a missing end node, want false")
	}
	if g.AddEdge("missing", "start", EdgeKindHasKeyMaterial, properties.NewProperties()) {
		t.Error("AddEdge() = true with a missing start node, want false")
	}

	g.EnsureNode("end", []string{NodeKindRSAPublicKey}, properties.NewProperties())
	if !g.AddEdge("start", "end", EdgeKindHasKeyMaterial, properties.NewProperties()) {
		t.Error("AddEdge() = false with both endpoints in the graph, want true")
	}

	if count := g.OG.GetEdgeCount(); count != 1 {
		t.Errorf("edge count = %d, want 1", count)
	}
}

func TestAddExternalEdgeDedupes(t *testing.T) {
	g := NewDedupedGraph("")

	for range 3 {
		if !g.AddExternalEdge("S-1-5-21-1-2-3-1104", "node-1", EdgeKindHasKeyCredential, properties.NewProperties()) {
			t.Fatal("AddExternalEdge() = false, want true")
		}
	}

	if count := g.OG.GetEdgeCount(); count != 1 {
		t.Errorf("edge count = %d, want 1: the same (start, end, kind) should only be added once", count)
	}

	if !g.AddExternalEdge("S-1-5-21-1-2-3-1104", "node-1", EdgeKindCanAuthenticateAs, properties.NewProperties()) {
		t.Fatal("AddExternalEdge() = false for a different kind, want true")
	}
	if count := g.OG.GetEdgeCount(); count != 2 {
		t.Errorf("edge count = %d, want 2", count)
	}
}

func TestAddExternalEdgeRejectsEmptyEndpoints(t *testing.T) {
	g := NewDedupedGraph("")

	if g.AddExternalEdge("", "node-1", EdgeKindHasKeyCredential, properties.NewProperties()) {
		t.Error("AddExternalEdge() = true with an empty start, want false")
	}
	if g.AddExternalEdge("node-1", "", EdgeKindHasKeyCredential, properties.NewProperties()) {
		t.Error("AddExternalEdge() = true with an empty end, want false")
	}
	if count := g.OG.GetEdgeCount(); count != 0 {
		t.Errorf("edge count = %d, want 0", count)
	}
}
