package shell

import "testing"

func TestRemoteKindOf(t *testing.T) {
	for text, want := range map[string]RemoteKind{
		"/tmp/r":                 RemoteKindLocal,
		"./r":                    RemoteKindLocal,
		"../r":                   RemoteKindLocal,
		"~/r":                    RemoteKindLocal,
		".":                      RemoteKindLocal,
		"..":                     RemoteKindLocal,
		"file:///tmp/r":          RemoteKindLocal,
		"https://github.com/a/b": RemoteKindHTTPS,
		"git@github.com:a/b":     RemoteKindSSH,
		"github.com:a/b":         RemoteKindSSH,
		"ssh://h/r":              RemoteKindSSH,
		"git+ssh://h/r":          RemoteKindSSH,
		"ssh+git://h/r":          RemoteKindSSH,
		"origin":                 RemoteKindUnknown,
		"http://h/r":             RemoteKindUnknown,
		"git://h/r":              RemoteKindUnknown,
		"ext::ssh -i k h %S r":   RemoteKindUnknown,
		"C:/r":                   RemoteKindLocal,
		"":                       RemoteKindUnknown,
	} {
		if got := RemoteKindOf(text); got != want {
			t.Errorf("RemoteKindOf(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestFirstOperand(t *testing.T) {
	k := func(s string) CommandWord { return CommandWord{Text: s, Known: true} }
	a := CommandWord{MayBeOption: true}
	u := CommandWord{}
	none := func(int) bool { return false }
	for _, c := range []struct {
		name  string
		words []CommandWord
		skip  func(int) bool
		at    int
		ok    bool
	}{
		{"after the subcommand", []CommandWord{k("git"), k("fetch"), k("/tmp/r"), a}, none, 2, true},
		{"after an option with a value", []CommandWord{k("git"), k("fetch"), k("--depth"), k("1"), k("/tmp/r"), a}, none, 4, true},
		{"after --", []CommandWord{k("git"), k("fetch"), k("--"), k("/tmp/r"), a}, none, 3, true},
		{"a word not known first", []CommandWord{k("git"), k("fetch"), u, a}, none, 2, true},
		{"the value only", []CommandWord{k("git"), k("fetch"), a}, none, 2, true},
		{"the value first, skipped", []CommandWord{k("git"), k("ls-remote"), a, k("/tmp/r")}, func(i int) bool { return i == 2 }, 3, true},
		{"after an undeclared option", []CommandWord{k("git"), k("fetch"), k("--frobnicate"), k("/tmp/r"), a}, none, 0, false},
		{"none", []CommandWord{k("git"), k("fetch")}, none, 0, false},
	} {
		at, ok := ArgumentRoles(c.words).FirstOperand(c.words, c.skip)
		if at != c.at || ok != c.ok {
			t.Errorf("%s: %d %v, want %d %v", c.name, at, ok, c.at, c.ok)
		}
	}
}
