package lint

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func TestParseVersion(t *testing.T) {
	v, err := ParseVersion("2.337.0")
	if err != nil || v.String() != "2.337.0" || v.IsZero() {
		t.Errorf("ParseVersion = %v, %v", v, err)
	}
	for _, s := range []string{"", "2.337", "v2.337.0", "2.337.0-beta", "02.1.0", "2..0"} {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("ParseVersion(%q): no error", s)
		}
	}
}

func TestParseCVE(t *testing.T) {
	c, err := ParseCVE("CVE-2025-30066")
	if err != nil || c.String() != "CVE-2025-30066" {
		t.Errorf("ParseCVE = %v, %v", c, err)
	}
	for _, s := range []string{"", "cve-2025-30066", "CVE-25-1234", "CVE-2025-123", "GHSA-mrrh-fwg8-r2c3"} {
		if _, err := ParseCVE(s); err == nil {
			t.Errorf("ParseCVE(%q): no error", s)
		}
	}
}

func repo(t *testing.T, s string) facts.Repo {
	t.Helper()
	r, err := facts.ParseRepo(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestThreatRejects: a precondition rests on something, an observation says
// when and what, an incident names what was attacked and where it is told.
func TestThreatRejects(t *testing.T) {
	seen := Observation{Date: MustDate("2026-09-24"), What: "seen"}
	src := MustCitation("https://example.com/advisory")
	for _, c := range []struct {
		name string
		edit func(*Threat)
		want string
	}{
		{"no actors", func(th *Threat) { th.Actors = nil }, "actor"},
		{"an actor without an attacker", func(th *Threat) { th.Actors[0].Attacker = AttackerUnset }, "the attacker AttackerUnset"},
		{"an attacker not in the schema", func(th *Threat) { th.Actors[0].Attacker = Attacker(200) }, "attacker"},
		{"an actor without gains", func(th *Threat) { th.Actors[0].Gains = nil }, "gain"},
		{"a zero gain", func(th *Threat) { th.Actors[0].Gains = []Gain{GainRunCode, GainUnset} }, "the gain GainUnset"},
		{"a gain twice", func(th *Threat) { th.Actors[0].Gains = []Gain{GainRunCode, GainRunCode} }, "twice"},
		{"an actor without via", func(th *Threat) { th.Actors[0].Via = " " }, "Via"},
		{"a zero event", func(th *Threat) { th.Actors[0].Events = []workflow.EventName{workflow.EventNameUnset} }, "event"},
		{"an event without a run starter", func(th *Threat) {
			th.Actors[0].Events = []workflow.EventName{workflow.EventNameIssueComment}
		}, "run starter"},
		{"a run starter of no event of the actor", func(th *Threat) {
			th.Actors[0].RunStarters = map[workflow.EventName]RunStarter{workflow.EventNameIssueComment: RunStarterAttacker}
		}, "run starter"},
		{"a zero run starter", func(th *Threat) {
			th.Actors[0].Events = []workflow.EventName{workflow.EventNameIssueComment}
			th.Actors[0].RunStarters = map[workflow.EventName]RunStarter{workflow.EventNameIssueComment: RunStarterUnset}
		}, "run starter"},
		{"a precondition without text", func(th *Threat) { th.Preconditions = []Precondition{{Cites: []Citation{src}}} }, "precondition"},
		{"a precondition resting on nothing", func(th *Threat) { th.Preconditions = []Precondition{{Text: "p"}} }, "precondition"},
		{"an observation without a date", func(th *Threat) {
			th.Preconditions = []Precondition{{Text: "p", Observed: []Observation{{What: "seen"}}}}
		}, "observation"},
		{"an observation without what", func(th *Threat) {
			th.Preconditions = []Precondition{{Text: "p", Observed: []Observation{{Date: MustDate("2026-09-24")}}}}
		}, "observation"},
		{"a zero cite", func(th *Threat) {
			th.Preconditions = []Precondition{{Text: "p", Observed: []Observation{seen}, Cites: []Citation{{}}}}
		}, "citation"},
		{"an incident with nothing compromised", func(th *Threat) {
			th.Incidents = []Incident{{Date: MustDate("2025-03-14"), Advisory: src, Downstream: []facts.Repo{repo(t, "a/b")}, Summary: "s"}}
		}, "incident"},
		{"an incident without a summary", func(th *Threat) {
			th.Incidents = []Incident{{Date: MustDate("2025-03-14"), Advisory: src, Compromised: []facts.Repo{repo(t, "a/b")}}}
		}, "incident"},
		{"a zero repository", func(th *Threat) {
			th.Incidents = []Incident{{Date: MustDate("2025-03-14"), Advisory: src, Compromised: []facts.Repo{{}}, Summary: "s"}}
		}, "incident"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := meta("r")
			m.FindingKinds = ownKinds("r")
			c.edit(&m.Threat)
			_, err := NewRegistry([]Rule{testRule{meta: m}})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestThreatJSON(t *testing.T) {
	m := ruleOf("r")
	m.Threat.Preconditions = []Precondition{{
		ID:   preconditionP,
		Text: "p",
		Observed: []Observation{
			{Date: MustDate("2026-09-24"), Runner: MustVersion("2.337.0"), What: "the runner ran it"},
			{Date: MustDate("2026-09-24"), What: "GitHub refused the push"},
		},
		Cites: []Citation{MustCitation("https://example.com/doc")},
	}}
	m.Threat.Actors = []Actor{
		{Attacker: AttackerForkPRAuthor, Via: "names the branch of the pull request", Events: []workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNamePush},
			RunStarters: map[workflow.EventName]RunStarter{workflow.EventNamePullRequestTarget: RunStarterAttacker, workflow.EventNamePush: RunStarterOther},
			Gains:       []Gain{GainRunCode, GainReadSecrets, GainWriteWithToken}},
		{Attacker: AttackerCommenter, Via: "writes the comment", Events: []workflow.EventName{workflow.EventNameIssueComment},
			RunStarters: map[workflow.EventName]RunStarter{workflow.EventNameIssueComment: RunStarterAttacker}, Gains: []Gain{GainRunCode}},
	}
	m.Threat.Incidents = []Incident{{ID: incidentI, Date: MustDate("2025-03-14"), CVE: MustCVE("CVE-2025-30066"),
		Advisory: MustCitation("https://example.com/advisory"), Compromised: []facts.Repo{repo(t, "Reviewdog/Action-Setup")},
		Downstream: []facts.Repo{repo(t, "reviewdog/action-typos")}, Summary: "tags moved"}}
	m.FindingKinds[0].Attackers = []Attacker{AttackerForkPRAuthor, AttackerCommenter}
	m.FindingKinds[0].FactKinds = []facts.Kind{facts.KindRepoPullRequestTargetAllowed} // pull_request_target is an event of its attackers
	m.FindingKinds[0].Incidents = []IncidentID{incidentI}
	m.FindingKinds[0].ExploitMaturity = Metric[ExploitMaturity]{Value: ExploitMaturityAttacked, Reason: "r"}
	reg, err := NewRegistry([]Rule{testRule{meta: m}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"actors":[{"attacker":"fork-pr-author","via":"names the branch of the pull request","events":["pull_request_target","push"],` +
			`"run_starters":[{"event":"pull_request_target","run_starter":"attacker"},{"event":"push","run_starter":"other"}],"gains":["run-code","read-secrets","write-with-token"]},` +
			`{"attacker":"commenter","via":"writes the comment","events":["issue_comment"],"run_starters":[{"event":"issue_comment","run_starter":"attacker"}],"gains":["run-code"]}]`,
		`"preconditions":[{"id":"p","text":"p","observed":[{"date":"2026-09-24","runner":"2.337.0","what":"the runner ran it"},{"date":"2026-09-24","what":"GitHub refused the push"}],"cites":["https://example.com/doc"]}]`,
		`"incidents":[{"id":"i","date":"2025-03-14","cve":"CVE-2025-30066","advisory":"https://example.com/advisory","compromised":["reviewdog/action-setup"],"downstream":["reviewdog/action-typos"],"summary":"tags moved"}]`,
		`"attackers":["fork-pr-author","commenter"],"preconditions":["p"],"incidents":["i"],"fixes":[],"fact_kinds":["repo.pull-request-target-allowed"]`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the JSON has no\n%s\nin\n%s", want, b)
		}
	}
}
