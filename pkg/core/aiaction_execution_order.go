package core

import (
	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// AIActionExecutionOrderRule は AI エージェントアクションがジョブの最後のステップでない場合を検出するルール。
//
// OpenAI Codex セキュリティチェックリストでは "Run Codex as the last step in a job" を推奨している。
// AI エージェントの後に他のステップが続くと、エージェントによる状態変更（ファイル変更、環境変数など）を
// 後続ステップが継承するリスクがある。
//
// 脆弱なパターン:
//
//	steps:
//	  - uses: actions/checkout@v4
//	  - uses: openai/codex-action@v1
//	    with:
//	      safety-strategy: drop-sudo
//	  - run: npm publish    # AI エージェントの後のステップ — 改変されたコードを公開する可能性
//
// 安全なパターン:
//
//	steps:
//	  - uses: actions/checkout@v4
//	  - uses: openai/codex-action@v1
//	    with:
//	      safety-strategy: drop-sudo
type AIActionExecutionOrderRule struct {
	BaseRule
}

// NewAIActionExecutionOrderRule は新しいルールインスタンスを返す。
func NewAIActionExecutionOrderRule() *AIActionExecutionOrderRule {
	return &AIActionExecutionOrderRule{
		BaseRule: BaseRule{
			RuleName: "ai-action-execution-order",
			RuleDesc: "AI action is not the last step in the job",
		},
	}
}

// VisitJobPre はジョブを訪問し、AI エージェントアクションの後に他のステップが続いていないかを検査する。
func (r *AIActionExecutionOrderRule) VisitJobPre(node *ast.Job) error {
	if node.Steps == nil {
		return nil
	}

	steps := node.Steps
	for i, step := range steps {
		action, ok := step.Exec.(*ast.ExecAction)
		if !ok {
			continue
		}

		if action.Uses == nil {
			continue
		}

		if !isKnownAIActionPrefix(action.Uses.Value) {
			continue
		}

		// AI アクションの後にステップが存在するかチェック
		if i < len(steps)-1 {
			r.Errorf(
				step.Pos,
				`action %q is not the last step in this job. The OpenAI/Anthropic security checklist recommends running AI agent actions as the last step to prevent subsequent steps from inheriting potentially compromised state.`,
				action.Uses.Value,
			)
		}
	}

	return nil
}
