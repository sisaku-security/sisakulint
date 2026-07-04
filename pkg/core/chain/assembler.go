// pkg/core/chain/assembler.go
package chain

import (
	"fmt"
	"sort"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// Assemble は AssemblerInput から ChainModel を組み立てる。
// 下半分（Source→Action→Sink）は Records のみを源とし、エッジを捏造しない。
// 上半分（Trigger/Permission）は JobContexts の文脈注釈。
func Assemble(in AssemblerInput) *ChainModel {
	m := &ChainModel{
		FilePath:     in.FilePath,
		WorkflowName: in.WorkflowName,
	}
	nodes := map[string]*Node{}
	ctxByJob := in.jobContextByID()

	getNode := func(n *Node) *Node {
		if ex, ok := nodes[n.ID]; ok {
			return ex
		}
		nodes[n.ID] = n
		return n
	}
	addEdge := func(from, to string, k EdgeKind) {
		m.Edges = append(m.Edges, Edge{From: from, To: to, Kind: k})
	}

	for _, r := range in.Records {
		sourceID := fmt.Sprintf("source:%d:%s", r.SourceKind, r.SourceName)
		actionID := fmt.Sprintf("action:%s:%d:%d", r.JobID, posLine(r.StepPos), posCol(r.StepPos))
		sinkID := fmt.Sprintf("sink:%s:%s:%d:%d", r.RuleName, r.JobID, posLine(r.StepPos), posCol(r.StepPos))

		getNode(&Node{ID: sourceID, Kind: NodeSource, Label: r.SourceName, Pos: r.StepPos,
			SourceKind: r.SourceKind, Untrusted: r.SourceKind == SourceUntrusted, JobID: r.JobID})
		getNode(&Node{ID: actionID, Kind: NodeAction, Label: r.StepSummary, Pos: r.StepPos, JobID: r.JobID})
		getNode(&Node{ID: sinkID, Kind: NodeSink, Label: r.SinkKind.String(), Pos: r.StepPos,
			SinkKind: r.SinkKind, RuleName: r.RuleName, Severity: r.Severity, JobID: r.JobID})

		addEdge(sourceID, actionID, EdgeUsedBy)
		addEdge(actionID, sinkID, EdgeFlowsTo)

		// 上半分の文脈接続
		if jc, ok := ctxByJob[r.JobID]; ok {
			permID := "perm:" + jc.JobID
			label := jc.Permission.Label
			if jc.Permission.Implicit {
				label = "implicit(default token)"
			}
			getNode(&Node{ID: permID, Kind: NodePermission, Label: label,
				Pos: jc.Permission.Pos, Implicit: jc.Permission.Implicit, JobID: jc.JobID})
			addEdge(permID, sourceID, EdgeEnables)
			for _, tr := range jc.Triggers {
				trID := "trigger:" + tr.Name
				getNode(&Node{ID: trID, Kind: NodeTrigger, Label: tr.Name, Pos: tr.Pos,
					Untrusted: tr.Untrusted, SecretsAvailable: tr.SecretsAvailable})
				addEdge(trID, permID, EdgeGrants)
			}
		}
	}

	m.Nodes = sortedNodes(nodes)
	dedupEdges(m)
	return m
}

func posLine(p *ast.Position) int {
	if p == nil {
		return 0
	}
	return p.Line
}
func posCol(p *ast.Position) int {
	if p == nil {
		return 0
	}
	return p.Col
}

// sortedNodes は (Kind, Line, Col, ID) で決定的順序に並べる。
func sortedNodes(nodes map[string]*Node) []*Node {
	out := make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if posLine(a.Pos) != posLine(b.Pos) {
			return posLine(a.Pos) < posLine(b.Pos)
		}
		if posCol(a.Pos) != posCol(b.Pos) {
			return posCol(a.Pos) < posCol(b.Pos)
		}
		return a.ID < b.ID
	})
	return out
}

// dedupEdges は重複エッジを除去し (From, To, Kind) でソートする。
func dedupEdges(m *ChainModel) {
	seen := map[Edge]bool{}
	uniq := m.Edges[:0]
	for _, e := range m.Edges {
		if seen[e] {
			continue
		}
		seen[e] = true
		uniq = append(uniq, e)
	}
	m.Edges = uniq
	sort.Slice(m.Edges, func(i, j int) bool {
		a, b := m.Edges[i], m.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})
}
