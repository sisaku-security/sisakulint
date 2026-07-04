// pkg/core/chain/model.go
package chain

import "github.com/sisaku-security/sisakulint/pkg/ast"

// NodeKind はチェーングラフのノード種別。
type NodeKind int

const (
	NodeTrigger NodeKind = iota
	NodePermission
	NodeSource
	NodeAction
	NodeSink
)

func (k NodeKind) String() string {
	switch k {
	case NodeTrigger:
		return "trigger"
	case NodePermission:
		return "permission"
	case NodeSource:
		return "source"
	case NodeAction:
		return "action"
	case NodeSink:
		return "sink"
	}
	return "unknown"
}

// SourceKind は source ノードの由来（secret か untrusted input か）。
type SourceKind int

const (
	SourceSecret SourceKind = iota
	SourceUntrusted
)

// SinkKind は終端の露出点の種別。
type SinkKind int

const (
	SinkLog SinkKind = iota
	SinkNetwork
	SinkArtifact
	SinkExpr
	SinkBoundary
)

func (k SinkKind) String() string {
	switch k {
	case SinkLog:
		return "log"
	case SinkNetwork:
		return "network"
	case SinkArtifact:
		return "artifact"
	case SinkExpr:
		return "expr"
	case SinkBoundary:
		return "boundary"
	}
	return "unknown"
}

// Node はチェーングラフの1ノード。種別ごとに使うフィールドが異なる（フラット構造）。
type Node struct {
	ID    string // モデル内で一意な安定 ID
	Kind  NodeKind
	Label string
	Pos   *ast.Position

	// Trigger / Source 用
	Untrusted bool
	// Trigger 用
	SecretsAvailable bool
	// Permission 用
	Implicit bool
	// Source 用
	SourceKind SourceKind
	// Sink 用
	SinkKind SinkKind
	RuleName string
	Severity string
	// Action / Sink 用
	JobID string

	// Assemble が計算する強調メタ
	ChainCount         int
	UntrustedReachable bool
	Leverage           bool
}

// EdgeKind はエッジ種別。Grants/Enables は文脈（破線）、それ以外はデータフロー（実線）。
type EdgeKind int

const (
	EdgeGrants  EdgeKind = iota // Trigger -> Permission
	EdgeEnables                 // Permission -> Source
	EdgeUsedBy                  // Source -> Action
	EdgeFlowsTo                 // Action -> Sink
	EdgeNeeds                   // 上流 job の Action -> 下流 Source
)

// IsContext は文脈エッジ（破線描画）なら true。
func (k EdgeKind) IsContext() bool { return k == EdgeGrants || k == EdgeEnables }

func (k EdgeKind) Label() string {
	switch k {
	case EdgeGrants:
		return "grants"
	case EdgeEnables:
		return "enables"
	case EdgeUsedBy:
		return "used-by"
	case EdgeFlowsTo:
		return "flows-to"
	case EdgeNeeds:
		return "needs"
	}
	return ""
}

// Edge は有向エッジ。
type Edge struct {
	From string
	To   string
	Kind EdgeKind
}

// Summary はグラフ単位の blast-radius サマリ。
type Summary struct {
	UntrustedTriggers int
	Secrets           int
	Sinks             int
	SinkCountsByKind  map[SinkKind]int
}

// ChainModel は1ワークフローファイルのチェーングラフ全体。
type ChainModel struct {
	FilePath     string
	WorkflowName string
	Nodes        []*Node
	Edges        []Edge
	Summary      Summary
	LeverageID   string // 最高レバレッジノードの ID（無ければ ""）
}
