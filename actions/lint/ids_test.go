package lint

import (
	"encoding/json"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"testing"
)

func TestParseRuleID(t *testing.T) {
	id, err := ParseRuleID("commit-sha")
	if err != nil || id.String() != "commit-sha" {
		t.Errorf("ParseRuleID(commit-sha) = %v, %v", id, err)
	}
	for _, s := range []string{"", "Commit-Sha", "a.b", "-a", "a-", "a--b", "1a"} {
		if _, err := ParseRuleID(s); err == nil {
			t.Errorf("ParseRuleID(%q): no error", s)
		}
	}
	if MustRuleID("a") != MustRuleID("a") {
		t.Error("two RuleIDs of the same name differ")
	}
	if _, err := json.Marshal(RuleID{}); err == nil {
		t.Error("Marshal of the zero RuleID: no error")
	}
}

func TestParseFixKindID(t *testing.T) {
	if _, err := ParseFixKindID("pin-sha"); err != nil {
		t.Errorf("ParseFixKindID(pin-sha): %v", err)
	}
	for _, s := range []string{"", "Pin", "a.b"} {
		if _, err := ParseFixKindID(s); err == nil {
			t.Errorf("ParseFixKindID(%q): no error", s)
		}
	}
	b, err := json.Marshal(MustFixKindID("pin-sha"))
	if err != nil || string(b) != `"pin-sha"` {
		t.Errorf("Marshal = %s, %v", b, err)
	}
}

func TestParseThreatIDs(t *testing.T) {
	if p, err := ParsePreconditionID("runner-writes"); err != nil || p.String() != "runner-writes" {
		t.Errorf("ParsePreconditionID = %v, %v", p, err)
	}
	if i, err := ParseIncidentID("tj-actions-2025"); err != nil || i.String() != "tj-actions-2025" {
		t.Errorf("ParseIncidentID = %v, %v", i, err)
	}
	for _, s := range []string{"", "Runner", "a_b", "a.b"} {
		if _, err := ParsePreconditionID(s); err == nil {
			t.Errorf("ParsePreconditionID(%q): no error", s)
		}
		if _, err := ParseIncidentID(s); err == nil {
			t.Errorf("ParseIncidentID(%q): no error", s)
		}
	}
	if b, err := json.Marshal(MustPreconditionID("wiki-open")); err != nil || string(b) != `"wiki-open"` {
		t.Errorf("the JSON of a PreconditionID is %s, %v", b, err)
	}
}

func TestParseCitation(t *testing.T) {
	if _, err := ParseCitation("https://docs.github.com/en/actions"); err != nil {
		t.Errorf("ParseCitation(https): %v", err)
	}
	for _, s := range []string{"", "http://example.com/x", "notes/x.md", "https://", "https:///x", "ftp://x/y", "https://a b/",
		// what the schema's pattern refuses
		"HTTPS://example.com/x", "Https://example.com/x", "https://:443/x", "https://x.com/a b", "https://x.com/\tx", "https://user@x.com/",
		// --explain writes a citation as an autolink, which cannot hold < or >
		"https://x.com/<a>", "https://x.com/a>", "https://<x>.com/"} {
		if _, err := ParseCitation(s); err == nil {
			t.Errorf("ParseCitation(%q): no error", s)
		}
	}
}

// TestInputPresentTakesAName pins what the type makes impossible:
// InputPresent of an empty string and of ./a.yml do not compile, and the
// zero Name is not
// written.
func TestInputPresentTakesAName(t *testing.T) {
	c := InputPresent(facts.MustCleanInputPath("./a.yml"))
	b, err := json.Marshal(c)
	if err != nil || string(b) != `{"input":"a.yml","present":true}` {
		t.Errorf("Marshal = %s, %v", b, err)
	}
	if _, err := json.Marshal(InputPresent(facts.InputPath{})); err == nil {
		t.Error("Marshal of InputPresent of the zero Name: no error")
	}
}

func TestFindingKindID(t *testing.T) {
	id, err := ParseFindingKindID("commit-sha.unpinned")
	if err != nil || id.String() != "commit-sha.unpinned" || id.Rule() != MustRuleID("commit-sha") || id.IsZero() {
		t.Errorf("ParseFindingKindID = %v, %v", id, err)
	}
	for _, s := range []string{"", "commit-sha", "commit-sha.", ".unpinned", "a.b.c", "Commit-sha.unpinned", "a.b c"} {
		if _, err := ParseFindingKindID(s); err == nil {
			t.Errorf("ParseFindingKindID(%q) takes it", s)
		}
	}
	if b, _ := MustFindingKindID("a-b.c").MarshalJSON(); string(b) != `"a-b.c"` {
		t.Errorf("MarshalJSON = %s", b)
	}
}
