// pkg/core/chain/mermaid.go
package chain

import (
	"fmt"
	"sort"
	"strings"
)

// MermaidRenderer は ChainModel を mermaid flowchart 文字列に描画する。
type MermaidRenderer struct{}

func NewMermaidRenderer() *MermaidRenderer { return &MermaidRenderer{} }

// sanitizeToken は [A-Za-z0-9_] 以外の全 rune を _ に写像し、mermaid の
// 識別子として安全なトークンを返す。SourceName は括弧・カンマ・引用符・
// アスタリスク（例: "expr (tainted via src)", "a, b", "secrets.*"）を含み得るため、
// 個別置換ではなくホワイトリストで正規化する。
func sanitizeToken(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// mermaidID は mermaid ノード ID に使えるよう記号を _ に正規化する。
func mermaidID(id string) string {
	return "n_" + sanitizeToken(id)
}

// escapeLabel は mermaid ラベル用に文字列を整形する。ノード定義は1行なので
// 複数行 run スクリプト等の改行は空白へ畳み、ラベルを壊す " のみ実体参照へ置換
// する。%q のような Go エスケープは使わない（\n / \\ をそのまま描画してしまう）。
func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, `"`, "&quot;")
}

// nodeShape は種別ごとの mermaid 形状で id["label"] を返す。ラベルは escapeLabel
// 済みの生テキストを二重引用符で囲む（%q は使わない。#6 参照）。
func nodeShape(n *Node) string {
	id := mermaidID(n.ID)
	label := escapeLabel(n.Label)
	switch n.Kind {
	case NodeTrigger:
		return fmt.Sprintf("%s([\"%s\"])", id, label)
	case NodePermission:
		return fmt.Sprintf("%s{{\"%s\"}}", id, label)
	case NodeSink:
		return fmt.Sprintf("%s>\"%s\"]", id, label)
	default: // NodeSource, NodeAction
		return fmt.Sprintf("%s[\"%s\"]", id, label)
	}
}

func (r *MermaidRenderer) Render(m *ChainModel) string {
	var b strings.Builder

	// mermaid は先頭行で図種別を判定する（detectType）。flowchart 宣言より前に
	// コメント行があると "No diagram type detected" になるため、必ず flowchart を
	// 最初に出す。① blast-radius サマリは診断メタなので直後の本文コメント行に置く
	b.WriteString("flowchart TD\n")
	fmt.Fprintf(&b, "  %%%% blast-radius: untrusted:%d secrets:%d sinks:%d (%s)\n",
		m.Summary.UntrustedTriggers, m.Summary.Secrets, m.Summary.Sinks, summarizeSinks(m.Summary))

	jobNodes := map[string][]*Node{}
	var outer []*Node
	for _, n := range m.Nodes {
		if (n.Kind == NodeAction || n.Kind == NodeSink) && n.JobID != "" {
			jobNodes[n.JobID] = append(jobNodes[n.JobID], n)
		} else {
			outer = append(outer, n)
		}
	}
	for _, n := range outer {
		fmt.Fprintf(&b, "  %s\n", nodeShapeWithBadge(n))
	}
	jobIDs := make([]string, 0, len(jobNodes))
	for j := range jobNodes {
		jobIDs = append(jobIDs, j)
	}
	sort.Strings(jobIDs)
	for _, j := range jobIDs {
		fmt.Fprintf(&b, "  subgraph job_%s[\"job: %s\"]\n", sanitizeToken(j), escapeLabel(j))
		for _, n := range jobNodes[j] {
			fmt.Fprintf(&b, "    %s\n", nodeShapeWithBadge(n))
		}
		b.WriteString("  end\n")
	}

	for _, e := range m.Edges {
		arrow := "-->"
		if e.Kind.IsContext() {
			arrow = "-.->"
		}
		fmt.Fprintf(&b, "  %s %s|%s| %s\n", mermaidID(e.From), arrow, e.Kind.Label(), mermaidID(e.To))
	}

	// ②④ classDef と class 割当
	b.WriteString("  classDef untrusted fill:#f88,stroke:#c00,color:#000\n")
	b.WriteString("  classDef safe fill:#eee,stroke:#bbb,color:#999\n")
	b.WriteString("  classDef fixhere stroke:#00a,stroke-width:3px\n")
	for _, n := range m.Nodes {
		cls := "safe"
		if n.UntrustedReachable {
			cls = "untrusted"
		}
		fmt.Fprintf(&b, "  class %s %s\n", mermaidID(n.ID), cls)
	}
	if m.LeverageID != "" {
		fmt.Fprintf(&b, "  class %s fixhere\n", mermaidID(m.LeverageID))
	}
	return b.String()
}

func summarizeSinks(s Summary) string {
	order := []SinkKind{SinkLog, SinkNetwork, SinkArtifact, SinkExpr, SinkBoundary}
	parts := []string{}
	for _, k := range order {
		if c := s.SinkCountsByKind[k]; c > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", k.String(), c))
		}
	}
	return strings.Join(parts, "/")
}

// nodeShapeWithBadge は共有ノード(ChainCount>1)に [&rarr;N sinks] を、
// レバレッジノードに 🔧 を付す。
func nodeShapeWithBadge(n *Node) string {
	label := n.Label
	if n.Leverage {
		label = "🔧 " + label
	}
	if n.ChainCount > 1 && (n.Kind == NodeTrigger || n.Kind == NodePermission || n.Kind == NodeSource) {
		label = fmt.Sprintf("%s [&rarr;%d sinks]", label, n.ChainCount)
	}
	tmp := *n
	tmp.Label = label
	return nodeShape(&tmp)
}
