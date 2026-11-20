package boundary

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

const pinned = "https://github.com/github/docs/blob/7b807926df3ccb7f3d1bcd4ad1c652fb42b0931d/content/actions/x.md"

func quote() Quote {
	return Quote{Citation: lint.MustCitation(pinned), Text: "a sentence", Retrieved: lint.MustDate("2026-10-08")}
}

func TestRowCheck(t *testing.T) {
	obs := lint.Observation{Date: lint.MustDate("2026-10-08"), What: "seen"}
	for _, c := range []struct {
		name string
		g    RunGrant
		ok   string // empty: valid; else a part of the error
	}{
		{"documented", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessWrite, Cache: AccessWrite, Secrets: SecretsAccessAll, Basis: BasisDocumented, Quotes: []Quote{quote()}}, ""},
		{"documented without a quote", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessWrite, Cache: AccessWrite, Secrets: SecretsAccessAll, Basis: BasisDocumented}, "quote"},
		{"observed", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisObserved, Observed: []lint.Observation{obs}}, ""},
		{"observed without an observation", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisObserved}, "observation"},
		{"unverified", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisUnverified, Uncertainty: "whether it has secrets"}, ""},
		{"unverified without what is not known", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisUnverified}, "uncertain"},
		{"no basis", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone}, "basis"},
		{"no head", RunGrant{Event: workflow.EventNameIssues, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisUnverified, Uncertainty: "x"}, "head"},
		{"no token", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisUnverified, Uncertainty: "x"}, "token"},
		{"no cache", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessRead, Secrets: SecretsAccessNone, Basis: BasisUnverified, Uncertainty: "x"}, "cache"},
		{"a quote of a moving branch", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisDocumented,
			Quotes: []Quote{{Citation: lint.MustCitation("https://github.com/github/docs/blob/main/content/actions/x.md"), Text: "a", Retrieved: lint.MustDate("2026-10-08")}}}, "commit"},
		{"a quote without text", RunGrant{Event: workflow.EventNameIssues, Head: PRHeadNone, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisDocumented,
			Quotes: []Quote{{Citation: lint.MustCitation(pinned), Retrieved: lint.MustDate("2026-10-08")}}}, "text"},
	} {
		err := c.g.check()
		switch {
		case c.ok == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.ok != "" && (err == nil || !strings.Contains(err.Error(), c.ok)):
			t.Errorf("%s: %v, want an error about %s", c.name, err, c.ok)
		}
	}
	if err := (RoleBaseline{Basis: BasisDocumented, Quotes: []Quote{quote()}}).check(); err == nil || !strings.Contains(err.Error(), "role") {
		t.Errorf("a baseline without a role: %v", err)
	}
	if err := (Channel{Attacker: lint.AttackerIssueAuthor, Basis: BasisDocumented, Quotes: []Quote{quote()}}).check(); err == nil || !strings.Contains(err.Error(), "role") {
		t.Errorf("a channel without a role: %v", err)
	}
}

func TestEnumJSON(t *testing.T) {
	b, err := json.Marshal([]any{RoleTriage, PRHeadFork, AccessWrite, SecretsAccessAll, BasisDocumented, CrossingByBaseline})
	if err != nil || string(b) != `["triage","fork","write","all","documented","by-baseline"]` {
		t.Errorf("%s %v", b, err)
	}
	if _, err := json.Marshal(RoleUnset); err == nil {
		t.Error("the zero Role is written")
	}
	if len(Roles()) != 6 || Roles()[0] != RoleNone || len(PRHeads()) != 3 {
		t.Errorf("%v %v", Roles(), PRHeads())
	}
}
