package lint

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseExampleNotes(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       ExampleNotes
		err        string
	}{
		{"three keys and a continuation", "# situation: the checkout leaves the token,\n#   and the upload takes it.\n# reason: the token still works.\n# cause: the rule reads a: b as one.\non: push\n",
			ExampleNotes{Situation: "the checkout leaves the token, and the upload takes it.", Reason: "the token still works.", Cause: "the rule reads a: b as one."}, ""},
		{"an empty comment line", "# situation: s\n#\n# reason: r\non: push\n", ExampleNotes{Situation: "s", Reason: "r"}, ""},
		{"CRLF", "# situation: s\r\n# reason: r\r\non: push\r\n", ExampleNotes{Situation: "s", Reason: "r"}, ""},
		{"a comment in the workflow is not read", "# situation: s\n# reason: r\non: push # situation: no\njobs: {}\n# cause: no\n", ExampleNotes{Situation: "s", Reason: "r"}, ""},
		{"free text before the keys", "# a note\n# situation: s\n# reason: r\non: push\n", ExampleNotes{}, "not a key"},
		{"an unknown key", "# situation: s\n# because: r\non: push\n", ExampleNotes{}, "not a key"},
		{"a key twice", "# situation: s\n# situation: t\non: push\n", ExampleNotes{}, "twice"},
		{"no comment", "on: push\n", ExampleNotes{}, ""},
		{"attack-value", "# situation: s\n# reason: r\n# attack-value: github.event.issue.title = \"a\\\"b\\n$(echo PWNED)`x`\\\\\"\n# attack-run-behavior: the shell runs it,\n#   and prints PWNED.\non: push\n",
			ExampleNotes{Situation: "s", Reason: "r", AttackValue: AttackValue{carrier: "github.event.issue.title", value: "a\"b\n$(echo PWNED)`x`\\"}, AttackRunBehavior: "the shell runs it, and prints PWNED."}, ""},
		{"attack", "# situation: s\n# reason: r\n# attack: the owner moves the tag v4,\n#   to a commit of theirs.\n# attack-run-behavior: the job runs it.\non: push\n",
			ExampleNotes{Situation: "s", Reason: "r", Attack: "the owner moves the tag v4, to a commit of theirs.", AttackRunBehavior: "the job runs it."}, ""},
		{"a carrier in prose", "# attack-value: the file pr_number.txt in the artifact = \"1\"\non: push\n",
			ExampleNotes{AttackValue: AttackValue{carrier: "the file pr_number.txt in the artifact", value: "1"}}, ""},
		{"attack-value goes on", "# attack-value: x = \"a\"\n#   b\non: push\n", ExampleNotes{}, "one line"},
		{"attack-value with no carrier", "# attack-value:  = \"a\"\non: push\n", ExampleNotes{}, "carrier"},
		{"attack-value with no =", "# attack-value: x \"a\"\non: push\n", ExampleNotes{}, "carrier"},
		{"attack-value not quoted", "# attack-value: x = a\non: push\n", ExampleNotes{}, "quoted"},
		{"attack-value a raw string", "# attack-value: x = `a`\non: push\n", ExampleNotes{}, "quoted"},
		{"attack-value with text after the string", "# attack-value: x = \"a\" b\non: push\n", ExampleNotes{}, "quoted"},
		{"two sources", "# situation: s\n# source: https://github.com/NVIDIA/OpenShell/blob/a408f5dd083a9a4be259bb44478598002f9387a6/.github/workflows/release-canary.yml#L189-L235\n# source: https://github.com/o/r/blob/0123456789abcdef0123456789abcdef01234567/a.yml\n# reason: r\non: push\n",
			ExampleNotes{Situation: "s", Reason: "r", Sources: []SourceFile{MustSourceFile("https://github.com/NVIDIA/OpenShell/blob/a408f5dd083a9a4be259bb44478598002f9387a6/.github/workflows/release-canary.yml#L189-L235"), MustSourceFile("https://github.com/o/r/blob/0123456789abcdef0123456789abcdef01234567/a.yml")}}, ""},
		{"a source goes on", "# source: https://github.com/o/r/blob/0123456789abcdef0123456789abcdef01234567/a.yml\n#   b\non: push\n", ExampleNotes{}, "one line"},
		{"a source twice", "# source: https://github.com/o/r/blob/0123456789abcdef0123456789abcdef01234567/a.yml\n# source: https://github.com/o/r/blob/0123456789abcdef0123456789abcdef01234567/a.yml#L1\non: push\n", ExampleNotes{}, "twice"},
		{"a source on a branch", "# source: https://github.com/o/r/blob/main/a.yml\non: push\n", ExampleNotes{}, "the note source"},
	} {
		got, err := ParseExampleNotes(c.text)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want %q", c.name, err, c.err)
		case c.err == "" && !reflect.DeepEqual(got, c.want):
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestExampleNotesCheck(t *testing.T) {
	sr := ExampleNotes{Situation: "s", Reason: "r", Attack: "a", AttackRunBehavior: "b"}
	src := sr
	src.Cause = "c"
	for _, c := range []struct {
		what ExampleWhat
		n    ExampleNotes
		ok   bool
	}{
		{ExampleTruePositive, sr, true}, {ExampleTruePositive, src, false},
		{ExampleTrueNegative, sr, true}, {ExampleTrueNegative, src, false},
		{ExampleFalsePositive, src, true}, {ExampleFalsePositive, sr, false},
		{ExampleUndetected, src, true}, {ExampleUndetected, sr, false},
		{ExampleInconclusive, sr, true}, {ExampleInconclusive, src, true},
		{ExampleTruePositive, ExampleNotes{Reason: "r"}, false},
		{ExampleTruePositive, ExampleNotes{Situation: "s"}, false},
		{ExampleTruePositive, ExampleNotes{Situation: "s", Reason: "r", Attack: "a", AttackValue: AttackValue{carrier: "x", value: "v"}}, false},
		{ExampleTruePositive, ExampleNotes{Situation: "s", Reason: "r", AttackValue: AttackValue{carrier: "x", value: ""}, AttackRunBehavior: "b"}, true},
		{ExampleTruePositive, ExampleNotes{Situation: "s", Reason: "r", AttackRunBehavior: "b"}, false},
		{ExampleTruePositive, ExampleNotes{Situation: "s", Reason: "r", Attack: "a"}, false},
	} {
		if err := c.n.check(c.what, false); (err == nil) != c.ok {
			t.Errorf("%s %+v: %v", c.what, c.n, err)
		}
	}
	q := ExampleNotes{Situation: "s", Reason: "r", Advisories: []AdvisoryPage{MustAdvisoryPage("https://github.com/advisories/GHSA-mrrh-fwg8-r2c3")}}
	if err := q.check(ExampleTruePositive, true); err == nil {
		t.Error("a quality rule's example with an advisory: no error")
	}
	q = ExampleNotes{Situation: "s", Reason: "r", Sources: []SourceFile{MustSourceFile("https://github.com/o/r/blob/0123456789abcdef0123456789abcdef01234567/a.yml")}}
	if err := q.check(ExampleTruePositive, true); err == nil {
		t.Error("a quality rule's example with a source: no error")
	}
}

// TestParseReviewedIsUnknown: the old mark # reviewed: is no key now; a
// person's approval is an approved document.
func TestParseReviewedIsUnknown(t *testing.T) {
	_, err := ParseExampleNotes("# situation: s\n# reason: r\n# reviewed: sha256:" + strings.Repeat("ab", 32) + "\non: push\n")
	if err == nil || !strings.Contains(err.Error(), "is not a key of the notes") {
		t.Errorf("err %v, want the error of a key not known", err)
	}
}

// TestParseExampleNotesAddedAttacker: the note added-attacker is one line
// each, an added attacker each, kept in the order of the values of
// AddedAttacker (the order of $defs/added-attacker of the schema of the
// registry), whatever the order of the file; a value not known, a value
// twice and a line that goes on are errors.
func TestParseExampleNotesAddedAttacker(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       []AddedAttacker
		err        string
	}{
		{"two", "# situation: s\n# added-attacker: variables-writer\n# added-attacker: secrets-writer\n# reason: r\non: push\n", []AddedAttacker{AddedAttackerVariablesWriter, AddedAttackerSecretsWriter}, ""},
		{"two, the order of the file not the order of the values", "# situation: s\n# added-attacker: secrets-writer\n# added-attacker: read-member\n# reason: r\non: push\n", []AddedAttacker{AddedAttackerReadMember, AddedAttackerSecretsWriter}, ""},
		{"not known", "# added-attacker: anyone\non: push\n", nil, "the note added-attacker"},
		{"twice", "# added-attacker: variables-writer\n# added-attacker: variables-writer\non: push\n", nil, "twice"},
		{"goes on", "# added-attacker: variables-writer\n#   and more\non: push\n", nil, "one line"},
	} {
		got, err := ParseExampleNotes(c.text)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: error %v, want %q", c.name, err, c.err)
		case c.err == "" && !reflect.DeepEqual(got.AddedAttackers, c.want):
			t.Errorf("%s: %v, want %v", c.name, got.AddedAttackers, c.want)
		}
	}
}

// TestExampleNotesCheckAddedAttacker: only a true positive of a rule has
// the note added-attacker.
func TestExampleNotesCheckAddedAttacker(t *testing.T) {
	n := ExampleNotes{Situation: "s", Reason: "r", Attack: "a", AttackRunBehavior: "b", AddedAttackers: []AddedAttacker{AddedAttackerVariablesWriter}}
	nc := n
	nc.Cause = "c"
	for _, c := range []struct {
		what ExampleWhat
		n    ExampleNotes
		ok   bool
	}{
		{ExampleTruePositive, n, true},
		{ExampleTrueNegative, n, false},
		{ExampleFalsePositive, nc, false},
		{ExampleUndetected, nc, false},
		{ExampleInconclusive, n, false},
	} {
		if err := c.n.check(c.what, false); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.what, err)
		}
	}
	q := ExampleNotes{Situation: "s", Reason: "r", AddedAttackers: []AddedAttacker{AddedAttackerVariablesWriter}}
	if err := q.check(ExampleTruePositive, true); err == nil {
		t.Error("a quality rule's example with an added attacker: no error")
	}
}
