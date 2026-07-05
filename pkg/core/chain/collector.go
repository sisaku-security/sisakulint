// pkg/core/chain/collector.go
package chain

import (
	"sync"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// SinkRecord は flow ルールが検出した 1件の source→sink データフローの構造化記録。
type SinkRecord struct {
	FilePath     string
	JobID        string // 小文字（ast.Workflow.Jobs のキーと一致）
	StepPos      *ast.Position
	StepSummary  string // "run: ..." / "uses: ..."
	SourceKind   SourceKind
	SourceName   string // 例 "secrets.DEPLOY_TOKEN" / "github.event.issue.title"
	SourceOrigin string // taint origin chain。"needs.build.outputs.ref" を含み得る
	SinkKind     SinkKind
	OutputName   string // Producer-side job output name for cross-job needs linking, when known.
	RuleName     string
	Severity     string
}

// SinkCollector は 1ファイル分の SinkRecord を集約する。Add は並行安全。
type SinkCollector struct {
	mu      sync.Mutex
	records []SinkRecord
}

func NewSinkCollector() *SinkCollector { return &SinkCollector{} }

// Add は記録を1件追加する（visitor がルールを並行実行し得るため mutex 保護）。
func (c *SinkCollector) Add(r SinkRecord) {
	c.mu.Lock()
	c.records = append(c.records, r)
	c.mu.Unlock()
}

// Records は記録のコピーを返す。
func (c *SinkCollector) Records() []SinkRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SinkRecord, len(c.records))
	copy(out, c.records)
	return out
}
