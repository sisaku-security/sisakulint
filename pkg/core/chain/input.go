// pkg/core/chain/input.go
package chain

import "github.com/sisaku-security/sisakulint/pkg/ast"

// TriggerRef は 1つの有効 trigger（job-level if 考慮済み）とその危険度属性。
type TriggerRef struct {
	Name             string
	Untrusted        bool // PrivilegedTriggers に含まれる等、攻撃者制御可能
	SecretsAvailable bool
	Pos              *ast.Position
}

// PermissionRef は job の実効パーミッション。
type PermissionRef struct {
	Label    string // "contents:write, id-token:write" 等。Implicit なら "implicit(default token)"
	Implicit bool   // permissions 未宣言（既定 GITHUB_TOKEN）
	Pos      *ast.Position
}

// JobContext は 1 job の trigger/permission 文脈。core 側アダプタが構築する。
type JobContext struct {
	JobID      string
	Triggers   []TriggerRef
	Permission PermissionRef
}

// AssemblerInput は Assemble への純データ入力。
type AssemblerInput struct {
	FilePath     string
	WorkflowName string
	JobContexts  []JobContext
	Records      []SinkRecord
}

// jobContextByID は JobID → *JobContext の索引を返す（Assemble 内部で使用）。
func (in AssemblerInput) jobContextByID() map[string]*JobContext {
	m := make(map[string]*JobContext, len(in.JobContexts))
	for i := range in.JobContexts {
		m[in.JobContexts[i].JobID] = &in.JobContexts[i]
	}
	return m
}
