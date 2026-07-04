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

// mermaidID は mermaid ノード ID に使えるよう記号を _ に正規化する。
func mermaidID(id string) string {
	r := strings.NewReplacer(":", "_", ".", "_", "-", "_", "/", "_", " ", "_")
	return "n_" + r.Replace(id)
}

// escapeLabel は mermaid ラベル内のダブルクォートを実体参照に置換する。
func escapeLabel(s string) string {
	return strings.ReplaceAll(s, `"`, "&quot;")
}

// nodeShape は種別ごとの mermaid 形状で id["label"] を返す。
func nodeShape(n *Node) string {
	id := mermaidID(n.ID)
	label := escapeLabel(n.Label)
	switch n.Kind {
	case NodeTrigger:
		return fmt.Sprintf("%s([%q])", id, label)
	case NodePermission:
		return fmt.Sprintf("%s{{%q}}", id, label)
	case NodeSource:
		return fmt.Sprintf("%s[%q]", id, label)
	case NodeAction:
		return fmt.Sprintf("%s[%q]", id, label)
	case NodeSink:
		return fmt.Sprintf("%s>%q]", id, label)
	}
	return fmt.Sprintf("%s[%q]", id, label)
}

func (r *MermaidRenderer) Render(m *ChainModel) string {
	var b strings.Builder
	b.WriteString("flowchart TD\n")

	// job ごとに Action/Sink をクラスタ化。Trigger/Permission/Source は外側。
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
		fmt.Fprintf(&b, "  %s\n", nodeShape(n))
	}
	jobIDs := make([]string, 0, len(jobNodes))
	for j := range jobNodes {
		jobIDs = append(jobIDs, j)
	}
	sort.Strings(jobIDs)
	for _, j := range jobIDs {
		fmt.Fprintf(&b, "  subgraph job_%s[\"job: %s\"]\n", j, escapeLabel(j))
		for _, n := range jobNodes[j] {
			fmt.Fprintf(&b, "    %s\n", nodeShape(n))
		}
		b.WriteString("  end\n")
	}

	// エッジ（m.Edges は Assemble で決定的順序済み）
	for _, e := range m.Edges {
		arrow := "-->"
		if e.Kind.IsContext() {
			arrow = "-.->"
		}
		fmt.Fprintf(&b, "  %s %s|%s| %s\n", mermaidID(e.From), arrow, e.Kind.Label(), mermaidID(e.To))
	}
	return b.String()
}
