// pkg/core/chain/assembler.go
package chain

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

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

	// SinkCollector.Add はルール並行実行時に呼び出し順が非決定になり得る
	// (collector.go 参照)。共有ノード（同一 source を複数 record が参照する
	// fan-out 等）は getNode の先着優先で Pos/JobID が確定するため、record を
	// 決定的な全順序に並べてから処理し、実行毎の描画ブレを防ぐ。
	// CLAUDE.md: 「Determinism is a hard requirement」。
	sortedRecords := append([]SinkRecord(nil), in.Records...)
	sort.Slice(sortedRecords, func(i, j int) bool {
		a, b := sortedRecords[i], sortedRecords[j]
		if la, lb := posLine(a.StepPos), posLine(b.StepPos); la != lb {
			return la < lb
		}
		if ca, cb := posCol(a.StepPos), posCol(b.StepPos); ca != cb {
			return ca < cb
		}
		if a.JobID != b.JobID {
			return a.JobID < b.JobID
		}
		if a.RuleName != b.RuleName {
			return a.RuleName < b.RuleName
		}
		if a.SourceKind != b.SourceKind {
			return a.SourceKind < b.SourceKind
		}
		if a.SourceName != b.SourceName {
			return a.SourceName < b.SourceName
		}
		return a.SinkKind < b.SinkKind
	})
	in.Records = sortedRecords

	for _, r := range in.Records {
		sourceID := sourceNodeID(r)
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

	linkCrossJobNeeds(m, nodes, in)
	computeChainCount(nodes, in)
	computeUntrustedReachable(nodes, m.Edges)
	computeSummary(m, nodes)
	m.LeverageID = computeLeverage(nodes)

	m.Nodes = sortedNodes(nodes)
	dedupEdges(m)
	return m
}

var needsOutputPattern = regexp.MustCompile(`needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)`)

func sourceNodeID(r SinkRecord) string {
	return fmt.Sprintf("source:%s:%d:%s", r.JobID, r.SourceKind, r.SourceName)
}

// linkCrossJobNeeds は SourceOrigin が needs.<job>.outputs.<name> を指す
// source に、同じ job output を生成したことが分かっている上流 Action
// ノードからだけ EdgeNeeds を張る。
func linkCrossJobNeeds(m *ChainModel, nodes map[string]*Node, in AssemblerInput) {
	// job -> output name -> that output's producer action node IDs.
	actionsByJobOutput := map[string]map[string][]string{}
	for _, r := range in.Records {
		if r.OutputName == "" {
			continue
		}
		actionID := fmt.Sprintf("action:%s:%d:%d", r.JobID, posLine(r.StepPos), posCol(r.StepPos))
		if _, ok := nodes[actionID]; !ok {
			continue
		}
		jobID := strings.ToLower(r.JobID)
		outputName := strings.ToLower(r.OutputName)
		if actionsByJobOutput[jobID] == nil {
			actionsByJobOutput[jobID] = map[string][]string{}
		}
		actionsByJobOutput[jobID][outputName] = append(actionsByJobOutput[jobID][outputName], actionID)
	}
	for _, r := range in.Records {
		mm := needsOutputPattern.FindStringSubmatch(r.SourceOrigin)
		if mm == nil {
			continue
		}
		upJob := strings.ToLower(mm[1])
		outputName := strings.ToLower(mm[2])
		sourceID := sourceNodeID(r)
		if _, ok := nodes[sourceID]; !ok {
			continue
		}
		for _, upActionID := range actionsByJobOutput[upJob][outputName] {
			m.Edges = append(m.Edges, Edge{From: upActionID, To: sourceID, Kind: EdgeNeeds})
		}
	}
}

// computeChainCount は各 record のパスが通過する全ノードの ChainCount を +1 する。
func computeChainCount(nodes map[string]*Node, in AssemblerInput) {
	ctxByJob := in.jobContextByID()
	for _, r := range in.Records {
		ids := []string{
			sourceNodeID(r),
			fmt.Sprintf("action:%s:%d:%d", r.JobID, posLine(r.StepPos), posCol(r.StepPos)),
			fmt.Sprintf("sink:%s:%s:%d:%d", r.RuleName, r.JobID, posLine(r.StepPos), posCol(r.StepPos)),
		}
		if jc, ok := ctxByJob[r.JobID]; ok {
			ids = append(ids, "perm:"+jc.JobID)
			for _, tr := range jc.Triggers {
				ids = append(ids, "trigger:"+tr.Name)
			}
		}
		for _, id := range ids {
			if n, ok := nodes[id]; ok {
				n.ChainCount++
			}
		}
	}
}

// computeUntrustedReachable は untrusted trigger と untrusted source を種に前方 BFS。
func computeUntrustedReachable(nodes map[string]*Node, edges []Edge) {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	queue := []string{}
	for id, n := range nodes {
		if (n.Kind == NodeTrigger && n.Untrusted) || (n.Kind == NodeSource && n.Untrusted) {
			n.UntrustedReachable = true
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nxt := range adj[cur] {
			if n, ok := nodes[nxt]; ok && !n.UntrustedReachable {
				n.UntrustedReachable = true
				queue = append(queue, nxt)
			}
		}
	}
}

func computeSummary(m *ChainModel, nodes map[string]*Node) {
	m.Summary.SinkCountsByKind = map[SinkKind]int{}
	for _, n := range nodes {
		switch n.Kind {
		case NodeTrigger:
			if n.Untrusted {
				m.Summary.UntrustedTriggers++
			}
		case NodeSource:
			if n.SourceKind == SourceSecret {
				m.Summary.Secrets++
			}
		case NodeSink:
			m.Summary.Sinks++
			m.Summary.SinkCountsByKind[n.SinkKind]++
		}
	}
}

// computeLeverage は非終端の共有ノード（Trigger/Permission/Source）の中で
// ChainCount 最大を選ぶ。タイは上流優先（Trigger > Permission > Source）、
// さらにタイなら ID 昇順で決定的に。選んだノードの Leverage を立てる。
func computeLeverage(nodes map[string]*Node) string {
	rank := map[NodeKind]int{NodeTrigger: 0, NodePermission: 1, NodeSource: 2}
	var best *Node
	for _, n := range nodes {
		r, ok := rank[n.Kind]
		if !ok {
			continue // 終端(Action/Sink)は対象外
		}
		if best == nil {
			best = n
			continue
		}
		br := rank[best.Kind]
		switch {
		case n.ChainCount != best.ChainCount:
			if n.ChainCount > best.ChainCount {
				best = n
			}
		case r != br:
			if r < br {
				best = n
			}
		default:
			if n.ID < best.ID {
				best = n
			}
		}
	}
	if best == nil {
		return ""
	}
	best.Leverage = true
	return best.ID
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
