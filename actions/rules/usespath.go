package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// UsesPath is the quality rule uses-path: a step's uses that GitHub does not
// read as written.
// The runner drops empty parts, reads a backslash of the path as /, and
// resolves . and .. as text; a path that goes above the root of its
// repository runs another directory's action, and one above the workspace
// a directory of the runner. The other rules read
// the action that runs; this rule says that the uses is written otherwise.
// It is upstream's obfuscation, without shell: cmd.
var UsesPath lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.UsesPathReader](usesPath{}, ir.UsesPathView))

// UsesPathID is the ID of uses-path.
var UsesPathID = lint.MustRuleID("uses-path")

type usesPath struct{}

func (usesPath) QualityMeta() lint.QualityMeta { return usesPathMeta }

func (usesPath) Check(_ context.Context, c *lint.RuleContext, v ir.UsesPathReader) error {
	for _, s := range v.UsesPathSites() {
		var args lint.FindingArgs
		switch s.Form() {
		case ir.UsesFormOutsideRepository:
			args = UsesPathOutsideRepository{Uses: s.UsesText()}
		case ir.UsesFormOutsideWorkspace:
			args = UsesPathOutsideWorkspace{Uses: s.UsesText()}
		default:
			args = UsesPathUnnormalizedPath{Uses: s.UsesText(), Normalized: s.Normalized()}
		}
		c.Report(lint.FindingDraft{Location: c.At(s.At()), Args: args})
	}
	return nil
}

var usesPathMeta = lint.QualityMeta{
	ID:       UsesPathID,
	Problem:  "a step's uses writes its owner, repository or path with parts that GitHub drops or resolves (empty parts such as // or a / before @, a part that is . or .., or, in a uses of another repository, a backslash, which GitHub reads as /), or with .. that goes above the root of the repository or of the workspace, so that the uses as written does not name the action that runs",
	Expected: "every uses names the action that runs as GitHub reads the uses: no empty part, no part that is . or .. (the ./ at the start of a local action stays), and / between the parts",
	Citations: []lint.Citation{
		lint.MustCitation("https://github.com/github/docs/blob/44a609d0382839fdfe455de859774cfebb7f2d83/content/actions/reference/workflows-and-actions/workflow-syntax.md"),
		lint.MustCitation(runnerSource + "src/Sdk/DTPipelines/Pipelines/ObjectTemplating/PipelineTemplateConverter.cs"),
		lint.MustCitation(runnerSource + "src/Runner.Worker/ActionManager.cs"),
	},
	Targets: []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FindingKinds: []lint.QualityFindingKind{
		{FindingText: textUsesPathOutsideRepository},
		{FindingText: textUsesPathOutsideWorkspace},
		{FindingText: textUsesPathUnnormalizedPath},
	},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("folded-uses"), Text: "a uses written as ${{ }} around a string literal (not a folded scalar of YAML), such as ${{ 'actions/checkout/./@v4' }}, which GitHub reads as the string: the rule reads only a uses written as the string itself", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("windows-runner"), Text: "a job on a Windows runner, where how the runner reads a backslash in a ./ or $/ path, and a path that differs from a directory only in upper and lower case, was not observed: the rule reads the uses as a Linux runner reads the uses, and does not look at letter case", Disposition: lint.Limitation(lint.DeciderRunTime)},
	}),
}
