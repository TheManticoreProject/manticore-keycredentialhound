package graph

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/gopengraph"
	"github.com/TheManticoreProject/gopengraph/edge"
	"github.com/TheManticoreProject/gopengraph/node"
	"github.com/TheManticoreProject/gopengraph/properties"
)

// DedupedGraph is an OpenGraph that remembers which edges it already holds.
//
// gopengraph's AddEdge compares a new edge against every edge already in the
// graph, which is quadratic in the number of edges and dominates the runtime on a
// domain holding many key credentials. Keeping the same (start, end, kind)
// deduplication in a map makes it constant time for an identical result.
type DedupedGraph struct {
	OG        *gopengraph.OpenGraph
	seenEdges map[string]struct{}
}

func NewDedupedGraph(sourceKind string) *DedupedGraph {
	return &DedupedGraph{
		OG:        gopengraph.NewOpenGraph(sourceKind),
		seenEdges: make(map[string]struct{}),
	}
}

// EnsureNode adds a node unless the graph already holds one with the same id, and
// reports whether the graph holds that node once it returns.
//
// An id already in the graph is not an error: node ids are derived from stable
// identifiers of the collected objects, so a collision means the same object was
// seen twice and the node already present describes it.
func (g *DedupedGraph) EnsureNode(id string, kinds []string, p *properties.Properties) bool {
	if g.OG.GetNode(id) != nil {
		return true
	}

	n, err := node.NewNode(id, kinds, p)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating node kind %s with id=%s: %s", kinds[0], id, err))
		return false
	}

	if !g.OG.AddNode(n) {
		logger.Warn(fmt.Sprintf("Error adding node kind %s with id=%s", kinds[0], id))
		return false
	}

	return true
}

// AddEdge adds an edge between two nodes of this graph.
func (g *DedupedGraph) AddEdge(startNodeId string, endNodeId string, kind string, p *properties.Properties) bool {
	if g.OG.GetNode(startNodeId) == nil {
		logger.Warn(fmt.Sprintf("Error adding edge (%s)---[%s]-->(%s): start node is not in the graph", startNodeId, kind, endNodeId))
		return false
	}
	if g.OG.GetNode(endNodeId) == nil {
		logger.Warn(fmt.Sprintf("Error adding edge (%s)---[%s]-->(%s): end node is not in the graph", startNodeId, kind, endNodeId))
		return false
	}

	return g.AddExternalEdge(startNodeId, endNodeId, kind, p)
}

// AddExternalEdge adds an edge without requiring its endpoints to be nodes of
// this graph. Cross-collector edges are resolved by BloodHound at ingest time
// against nodes collected elsewhere, so they cannot be validated here.
func (g *DedupedGraph) AddExternalEdge(startNodeId string, endNodeId string, kind string, p *properties.Properties) bool {
	key := kind + "\x00" + startNodeId + "\x00" + endNodeId
	if _, seen := g.seenEdges[key]; seen {
		return true
	}

	e, err := edge.NewEdge(startNodeId, endNodeId, kind, p)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating edge (%s)---[%s]-->(%s): %s", startNodeId, kind, endNodeId, err))
		return false
	}

	if !g.OG.AddEdgeWithoutValidation(e) {
		logger.Warn(fmt.Sprintf("Error adding edge: (%s)---[%s]-->(%s)", startNodeId, kind, endNodeId))
		return false
	}

	g.seenEdges[key] = struct{}{}

	return true
}
