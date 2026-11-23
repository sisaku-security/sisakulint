package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// CacheBloat is the quality rule cache-bloat: a save that may carry the
// content of an older cache, restored by restore-keys, into a new one.
// A restore of the exact key only is not reported: GitHub saves nothing
// under a key it has.
var CacheBloat lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.CacheBloatReader](cacheBloat{}, ir.CacheBloatView))

// CacheBloatID is the ID of cache-bloat.
var CacheBloatID = lint.MustRuleID("cache-bloat")

type cacheBloat struct{}

func (cacheBloat) QualityMeta() lint.QualityMeta { return cacheBloatMeta }

func (cacheBloat) Check(_ context.Context, c *lint.RuleContext, v ir.CacheBloatReader) error {
	for _, s := range v.CacheRestoreSaves() {
		if len(s.SavesOn()) == 0 {
			continue
		}
		d := lint.FindingDraft{Location: c.At(s.SaveAt()), Args: CacheBloatPartialRestore{SavesOn: s.SavesOn()}}
		switch {
		case len(s.Chain()) > 0:
			// actions/cache in a composite action of another repository
			d.Anchor = placeAnchor(c, s.Chain(), s.RestoreAt())
			d.Related = []lint.Related{{Location: c.At(s.RestoreAt()), Note: "restores with restore-keys and saves, in the composite action " + s.Chain()[len(s.Chain())-1].Uses}}
		case s.Separate():
			d.Related = []lint.Related{{Location: c.At(s.RestoreAt()), Note: "restores with restore-keys"}}
		}
		c.Report(d)
	}
	return nil
}

var cacheBloatMeta = lint.QualityMeta{
	ID:       CacheBloatID,
	Problem:  "a step saves under a new key the content of a cache that restore-keys restored from another key, so the content of the older caches stays in each new cache",
	Expected: "a cache is saved only by a run in which restore-keys restored no older cache",
	Citations: []lint.Citation{
		lint.MustCitation("https://github.com/actions/cache/blob/3edfce9056124e459a23f683a21433670d47daca/tips-and-workarounds.md"),
		lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#cache-key-matching"),
	},
	Targets:      []lint.InputKind{lint.InputKindWorkflow},
	FindingKinds: []lint.QualityFindingKind{{FindingText: textCacheBloatPartialRestore}},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("expression-restore-keys"), Text: "restore-keys written only as ${{ }}, whose value may be empty when the workflow runs; with an empty value, the step restores no cache of another key", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("key-prefix"), Text: "a restore without restore-keys whose key is a prefix of the key that a later step saves; GitHub restores a cache whose key starts with the prefix", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-action"), Text: "a cache of another action, such as the cache input of actions/setup-node; or, in a composite action of another repository, an actions/cache/restore and a later save, or actions/cache when action.definition has no answer for the composite action (a run without --online and without the answer in --facts)", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("path-spelling"), Text: "a restore and a save that name one directory in two spellings, such as ~/.npm and /home/runner/.npm; the rule compares the lines of path as text", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("pruned-path"), Text: "a path whose content the build or the tool prunes on each run, so that the content of the older caches does not stay in the new cache", FindingKinds: []lint.FindingKindID{kindCacheBloatPartialRestore}, Disposition: lint.Limitation(lint.DeciderRunTime)},
	},
}
