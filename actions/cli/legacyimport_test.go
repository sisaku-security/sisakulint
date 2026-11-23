package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

func items(texts ...string) legacyList {
	l := legacyList{present: true}
	for i, s := range texts {
		l.items = append(l.items, legacyItem{s, i + 2})
	}
	return l
}

func noteTexts(ns []legacyNote) []string {
	var s []string
	for _, n := range ns {
		s = append(s, n.text)
	}
	return s
}

// mentions is whether one of texts has every one of words.
func mentions(texts []string, words ...string) bool {
	for _, s := range texts {
		all := true
		for _, w := range words {
			all = all && strings.Contains(s, w)
		}
		if all {
			return true
		}
	}
	return false
}

func TestLegacyActionList(t *testing.T) {
	for _, l := range []legacyList{{}, {present: true, null: true}, {present: true}} {
		if f, notes := legacyActionList(l); f != nil || len(notes) != 0 {
			t.Errorf("%+v: fact %+v, notes %q; want none", l, f, noteTexts(notes))
		}
	}

	f, notes := legacyActionList(items("actions/checkout@*", "Actions/Setup-Go@*"))
	if f == nil {
		t.Fatal("no fact")
	}
	if f.kind != facts.KindRepoActionList || f.args != "" {
		t.Errorf("kind, args = %v, %q", f.kind, f.args)
	}
	if want := []string{`"actions/checkout@*"`, `"Actions/Setup-Go@*"`}; !reflect.DeepEqual(f.list, want) {
		t.Errorf("list = %q, want %q", f.list, want)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %q", noteTexts(notes))
	}
	for _, words := range [][]string{{"jobs", "action metadata"}, {"case"}, {"./"}, {"container", "service"}, {"as GitHub reads"}} {
		if !mentions(f.notes, words...) {
			t.Errorf("no difference names %q: %q", words, f.notes)
		}
	}
	if got := f.factText(); got != `repo.action-list=["actions/checkout@*", "Actions/Setup-Go@*"]` {
		t.Errorf("factText = %s", got)
	}

	f, notes = legacyActionList(items("!evil/x@*", "a b", "./local", "ok/x@*"))
	if f == nil || !reflect.DeepEqual(f.list, []string{`"ok/x@*"`}) {
		t.Fatalf("fact = %+v", f)
	}
	got := noteTexts(notes)
	if len(got) != 3 || !mentions(got, `"!evil/x@*"`, "line 2") || !mentions(got, `"a b"`, "line 3") || !mentions(got, `"./local"`, "line 4") {
		t.Errorf("notes = %q", got)
	}

	f, notes = legacyActionList(items("!evil/x@*"))
	if f == nil || len(f.list) != 0 || len(notes) != 1 {
		t.Fatalf("fact = %+v, notes = %q", f, noteTexts(notes))
	}
	if got := f.factText(); got != `repo.action-list=[]` {
		t.Errorf("factText = %s", got)
	}
}

func TestLegacyConfigurationVariables(t *testing.T) {
	for _, l := range []legacyList{{}, {present: true, null: true}} {
		if f, notes := legacyConfigurationVariables(l); f != nil || len(notes) != 0 {
			t.Errorf("%+v: fact %+v, notes %q; want none", l, f, noteTexts(notes))
		}
	}

	f, _ := legacyConfigurationVariables(legacyList{present: true})
	if f == nil || len(f.list) != 0 || f.factText() != `repo.configuration-variables=[]` {
		t.Errorf("empty list: fact = %+v", f)
	}

	f, notes := legacyConfigurationVariables(items("foo", "BAR"))
	if f == nil {
		t.Fatal("no fact")
	}
	if f.kind != facts.KindRepoConfigurationVariables || f.args != "" {
		t.Errorf("kind, args = %v, %q", f.kind, f.args)
	}
	if want := []string{`"FOO"`, `"BAR"`}; !reflect.DeepEqual(f.list, want) {
		t.Errorf("list = %q, want %q", f.list, want)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %q", noteTexts(notes))
	}
	for _, words := range [][]string{{"environment"}, {"compared"}, {"--online"}} {
		if !mentions(f.notes, words...) {
			t.Errorf("no difference names %q: %q", words, f.notes)
		}
	}

	f, _ = legacyConfigurationVariables(items("foo", "FOO", "Foo"))
	if f == nil || !reflect.DeepEqual(f.list, []string{`"FOO"`}) {
		t.Errorf("one name in three cases: fact = %+v, want FOO once", f)
	}

	f, notes = legacyConfigurationVariables(items("GITHUB_X", "1A", "a-b", ""))
	if f == nil || len(f.list) != 0 {
		t.Fatalf("fact = %+v", f)
	}
	if got := noteTexts(notes); len(got) != 4 || !mentions(got, `"GITHUB_X"`, "line 2") || !mentions(got, `""`, "line 5") {
		t.Errorf("notes = %q", got)
	}
}
