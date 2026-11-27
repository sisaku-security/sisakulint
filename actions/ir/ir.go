package ir

//go:generate go run ./internal/irgen

import (
	"context"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"sync"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/labeler"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// IR is what the rules of one input read. The summaries of a type are
// made the first time a rule asks for them: once for the IR and the type.
type IR struct {
	input    string
	name     calls.Node             // input as a node of the call graph; zero when it is none
	callers  func() *taint.Callers  // the callers among the inputs of the run; nil: none
	labelers func() *labeler.Table  // the steps that run actions/labeler on an attacker's pull request; nil: none
	barriers analysis.BarrierPasses // the barriers the attacker of the run gets past (WithBarriers)
	// the reader of the actions steps run, and the context of the run it
	// asks the facts in (WithComposite); nil: none is read
	composites *composite.Reader
	ctx        context.Context
	origin     *composite.Origin // the file of a remote called workflow (NewRemote); nil for an input
	tree       *cst.Tree
	workflow   *workflow.Workflow       // when the input is a workflow
	action     *workflow.ActionMetadata // when it is an action.yml
	paths      *Paths
	editor     edit.Editor // keeps what it looks up in the tree, for every fix of the input

	skipped          skippedJobs // the jobs GitHub skips in every run (alwaysSkipped)
	onces            [summaryCount]sync.Once
	panics           [summaryCount]any // what the making of each type panicked with
	made             [summaryCount]int
	uses             []*Uses
	unreadCallees    []*UnreadCallee
	checkoutSites    []*CheckoutSite
	checkoutSiteOf   map[*CheckoutSite]prcode.CheckoutSite // what the fixes of a site read (checkoutfix.go)
	runCheckoutSites []*RunCheckoutSite

	scripts  *shell.Memo    // each script read once, for taint, prcode and the plans
	analysis taint.Analysis // made with the Sinks, which the plans read
	analyzed int            // how many times taint.Analyze ran, for the tests
	sinks    []*Sink
	fixes    []*StepFix
	plan     *stepPlan

	uploads         []*Upload
	leftCredentials []*LeftCredential
	stepOf          map[*LeftCredential]*workflow.Step // what the fix of a left credential reads (upload.go)

	downloadSites  []*DownloadSite
	downloadSiteOf map[*DownloadSite]prcode.DownloadSite // what the fix of a download reads (download.go)

	jobs []*Job

	imageSites                []*ImageSite
	registryCredentials       []*RegistryCredentials
	jobTimeouts               []*JobTimeout
	cacheRestoreSaves         []*CacheRestoreSave
	dependencyReviewSteps     []*DependencyReviewStep
	runsUsingSites            []*RunsUsingSite
	nodeRuntimeSettings       []*NodeRuntimeSetting
	setupNodeVersions         []*SetupNodeVersion
	usesPathSites             []*UsesPathSite
	secretsContextReads       []*SecretsContextRead
	secretParts               []*SecretPart
	printedOutputs            []*PrintedOutput
	mixedIfs                  []*MixedIf
	envKeys                   []*EnvKey
	expressionMistakes        []*ExpressionMistake
	configurationVariableRefs []*ConfigurationVariableRef

	ifSites    []*IfSite
	ifSiteOf   map[*IfSite]workflow.Field[workflow.If] // what the fixes of a site read (if.go)
	agentSteps []*AgentStep

	compositeCalls []*CompositeCall
	remoteCalls    []*RemoteCall

	cacheSaves         []*CacheSave
	requestActionSites []*RequestActionSite
	cacheModeOf        map[*Job]workflow.Field[workflow.String] // what the fix of a job's cache-mode reads (cache.go)
	cacheModeJob       map[*Job]*workflow.Job                   // and of the job it is of
}

// New is the IR of the input named input (as the engine names it), whose
// tree is t and whose model is w or a.
func New(input string, t *cst.Tree, w *workflow.Workflow, a *workflow.ActionMetadata) *IR {
	var name calls.Node
	if n, err := facts.CleanInputPath(input); err == nil {
		name = calls.InputNode(n)
	}
	return &IR{input: input, name: name, tree: t, workflow: w, action: a, paths: NewPaths(), checkoutSiteOf: map[*CheckoutSite]prcode.CheckoutSite{}, scripts: shell.NewMemo(), stepOf: map[*LeftCredential]*workflow.Step{}, downloadSiteOf: map[*DownloadSite]prcode.DownloadSite{}, ifSiteOf: map[*IfSite]workflow.Field[workflow.If]{}, cacheModeOf: map[*Job]workflow.Field[workflow.String]{}, cacheModeJob: map[*Job]*workflow.Job{}}
}

// NewRemote is the IR of the remote called workflow r: its places are in
// the value of the fact it is read from, and it reads its events and
// inputs from its caller (WithCallers).
func NewRemote(r *calls.RemoteCalled) *IR {
	x := New("", r.Called.Origin.Tree, r.Called.Workflow, nil)
	x.name, x.origin = calls.RemoteNode(r), &r.Called.Origin
	return x
}

// ownEventsOn are the events of names that the on of the workflow of x
// starts it on: none for a remote called workflow, whose on starts runs in
// its own repository.
func (x *IR) ownEventsOn(names []workflow.EventName) []analysis.EventActivity {
	if x.origin != nil || x.workflow == nil {
		return nil
	}
	return taint.EventsOn(x.workflow, names)
}

// WithCallers is x, which reads the callers of its input from callers,
// called the first time a summary asks: the events and the inputs of a
// called workflow or action.
func (x *IR) WithCallers(callers func() *taint.Callers) *IR {
	x.callers = callers
	return x
}

// WithLabelers is x, which reads the steps of the repository that run
// actions/labeler on an attacker's pull request from labelers, called the
// first time a summary asks.
func (x *IR) WithLabelers(labelers func() *labeler.Table) *IR {
	x.labelers = labelers
	return x
}

// WithBarriers is x, read in a run whose attacker gets past p: the run
// adds an attacker (lint's AddedAttacker).
func (x *IR) WithBarriers(p analysis.BarrierPasses) *IR {
	x.barriers = p
	return x
}

// table is the attacker run table x reads the ifs in.
func (x *IR) table() attacker.Table { return attacker.TableOf(x.barriers) }

// labelersOf are the labeler steps x reads, or nil.
func (x *IR) labelersOf() *labeler.Table {
	if x.labelers == nil {
		return nil
	}
	return x.labelers()
}

// WithComposite is x, which reads the actions its steps run with r, asking
// the facts of the actions of other repositories in ctx, the context of
// the run (CompositeCall).
func (x *IR) WithComposite(ctx context.Context, r *composite.Reader) *IR {
	x.ctx, x.composites = ctx, r
	return x
}

// callersOf are the callers x reads, or nil.
func (x *IR) callersOf() *taint.Callers {
	if x.callers == nil {
		return nil
	}
	return x.callers()
}

// RuleAccess is a new record of what one rule reads of x.
func (x *IR) RuleAccess() *RuleAccess { return &RuleAccess{ir: x} }

// Made is how many times the summaries of t were made: once when a rule
// asked for them, none when no rule did.
func (x *IR) Made(t SummaryType) int { return x.made[t] }

// once makes the summaries of t with f the first time it is called for t.
// f may ask for the summaries of another type, which are made then (the
// summary types a type is made of: StepFix of Sink). f sets the summaries
// at its end, so that none is left half made. When f panics, every call
// for t panics the same, so that each rule that reads them fails and none
// reads nothing in silence.
func (x *IR) once(t SummaryType, f func()) {
	x.onces[t].Do(func() {
		defer func() {
			if p := recover(); p != nil {
				x.panics[t] = p
			}
		}()
		f()
		x.made[t]++
	})
	if p := x.panics[t]; p != nil {
		panic(p)
	}
}
