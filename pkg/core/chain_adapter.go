// pkg/core/chain_adapter.go
package core

import (
	"sort"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/core/chain"
)

// workflowTriggerInfos は workflow.On からイベント名と位置を抽出する。
func workflowTriggerInfos(wf *ast.Workflow) []TriggerInfo {
	infos := make([]TriggerInfo, 0, len(wf.On))
	for _, ev := range wf.On {
		name := ev.EventName()
		var pos *ast.Position
		if we, ok := ev.(*ast.WebhookEvent); ok {
			pos = we.Pos
		}
		infos = append(infos, TriggerInfo{Name: name, Pos: pos})
	}
	return infos
}

// permissionRef は workflow/job の permissions を表示用にまとめる。job が未宣言なら workflow を継承、両方無ければ Implicit。
func permissionRef(wf *ast.Workflow, job *ast.Job) chain.PermissionRef {
	p := job.Permissions
	if p == nil {
		p = wf.Permissions
	}
	if p == nil {
		return chain.PermissionRef{Label: "implicit(default token)", Implicit: true}
	}
	if p.All != nil {
		return chain.PermissionRef{Label: "all:" + p.All.Value, Pos: p.Pos}
	}
	scopes := make([]string, 0, len(p.Scopes))
	for name, sc := range p.Scopes {
		if sc != nil && sc.Value != nil {
			scopes = append(scopes, name+":"+sc.Value.Value)
		}
	}
	sort.Strings(scopes)
	return chain.PermissionRef{Label: strings.Join(scopes, ", "), Pos: p.Pos}
}

// buildAssemblerInput は AST + records から純データ入力を構築する（JobTriggerAnalyzer で job-level if を考慮）。
func buildAssemblerInput(filePath string, wf *ast.Workflow, records []chain.SinkRecord) chain.AssemblerInput {
	name := ""
	if wf.Name != nil {
		name = wf.Name.Value
	}
	analyzer := NewJobTriggerAnalyzerWithPositions(workflowTriggerInfos(wf))

	jobIDs := make([]string, 0, len(wf.Jobs))
	for id := range wf.Jobs {
		jobIDs = append(jobIDs, id)
	}
	sort.Strings(jobIDs)

	contexts := make([]chain.JobContext, 0, len(jobIDs))
	for _, id := range jobIDs {
		job := wf.Jobs[id]
		triggerNames := analyzer.AnalyzeJobTriggers(job)
		trs := make([]chain.TriggerRef, 0, len(triggerNames))
		for _, tn := range triggerNames {
			info := analyzer.GetMatchedPrivilegedTrigger(job) // 位置取得補助（無ければ nil）
			var pos *ast.Position
			if info != nil && info.Name == tn {
				pos = info.Pos
			}
			trs = append(trs, chain.TriggerRef{
				Name:             tn,
				Untrusted:        PrivilegedTriggers[tn],
				SecretsAvailable: PrivilegedTriggers[tn],
				Pos:              pos,
			})
		}
		contexts = append(contexts, chain.JobContext{
			JobID:      id,
			Triggers:   trs,
			Permission: permissionRef(wf, job),
		})
	}
	return chain.AssemblerInput{FilePath: filePath, WorkflowName: name, JobContexts: contexts, Records: records}
}
