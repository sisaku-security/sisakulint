package shell

import (
	"slices"
	"strings"
	"testing"
)

// known is the words of s split at blanks, each known but those that
// begin with $.
func known(s string) []CommandWord {
	var out []CommandWord
	for _, w := range strings.Fields(s) {
		out = append(out, CommandWord{Text: w, Known: !strings.HasPrefix(w, "$")})
	}
	return out
}

func entryName(e *CommandEntry) string {
	if e == nil {
		return ""
	}
	return strings.Join(append([]string{e.Names[0]}, e.Subcommand...), " ")
}

func TestLookupCommand(t *testing.T) {
	for _, c := range []struct {
		words    string
		entry    string
		wrappers []string
		extent   MatchExtent
		readings map[int]ArgumentReading
	}{
		{"git -C dir push origin main", "git push", nil, MatchComplete, nil},
		{"/usr/bin/git status", "git status", nil, MatchComplete, nil},
		{"timeout 30 npm test", "npm test", []string{"timeout"}, MatchComplete, nil},
		{"env -u X A=1 B=2 make", "make", []string{"env"}, MatchComplete, nil},
		{"sudo -u bob nohup gh issue view 12", "gh issue view", []string{"sudo", "nohup"}, MatchComplete, nil},
		{"gh issue edit 12 --add-label x", "gh issue edit", nil, MatchStopped, nil},
		{"gh issue edit -R o/r 12", "gh issue edit", nil, MatchComplete, nil},
		{"git --frob push", "git", nil, MatchStopped, nil},
		{"no-such-command x", "", nil, MatchNone, nil},
		{"$CMD x", "", nil, MatchStopped, nil},
		{"nohup", "", []string{"nohup"}, MatchStopped, nil},
		{"timeout $T make", "timeout", nil, MatchStopped, nil},
		{"bash -c echo x", "bash", nil, MatchComplete, map[int]ArgumentReading{2: ArgumentReadingCode}},
		{"python3 -cprint(1)", "python", nil, MatchComplete, map[int]ArgumentReading{1: ArgumentReadingCode}},
		{"eval a b", "eval", nil, MatchComplete, map[int]ArgumentReading{1: ArgumentReadingCode, 2: ArgumentReadingCode}},
		{"eval $x", "eval", nil, MatchStopped, nil},
		{"grep -- -x", "grep", nil, MatchComplete, nil},
		{"git -c core.fsmonitor=x status", "git status", nil, MatchComplete, map[int]ArgumentReading{2: ArgumentReadingProgram}},
		{"git --exec-path=/x status", "git status", nil, MatchComplete, map[int]ArgumentReading{1: ArgumentReadingProgram}},
		{"setsid -f make", "make", []string{"setsid"}, MatchComplete, nil},
		{"git grep -c pat", "git", nil, MatchStopped, nil},
		{"git rebase main", "git", nil, MatchStopped, nil},
		{"git --no-pager log -1", "git log", nil, MatchStopped, nil},
	} {
		t.Run(c.words, func(t *testing.T) {
			ws := known(c.words)
			m := LookupCommand(ws)
			if got := entryName(m.Entry); got != c.entry {
				t.Errorf("entry %q, want %q", got, c.entry)
			}
			var wr []string
			for _, w := range m.Wrappers {
				wr = append(wr, w.Names[0])
			}
			if !slices.Equal(wr, c.wrappers) {
				t.Errorf("wrappers %v, want %v", wr, c.wrappers)
			}
			if m.Extent != c.extent {
				t.Errorf("extent %v, want %v", m.Extent, c.extent)
			}
			for i := range ws {
				if m.Readings[i] != c.readings[i] {
					t.Errorf("word %d: reading %v, want %v", i, m.Readings[i], c.readings[i])
				}
			}
		})
	}
}

// TestWordsOf: a word with an expansion in it is not known.
func TestWordsOf(t *testing.T) {
	src := `git -C "dir" push "$R" 'x y'`
	sc := Parse(src)
	s := sc.List[0].(*Simple)
	got := WordsOf(src, s)
	want := []CommandWord{{Text: "git", Known: true}, {Text: "-C", Known: true}, {Text: "dir", Known: true}, {Text: "push", Known: true}, {}, {Text: "x y", Known: true}}
	if !slices.Equal(got, want) {
		t.Errorf("WordsOf = %v, want %v", got, want)
	}
}

// TestSubcommands: the entries under an entry, at any depth, in the order of
// their words; none under a command without subcommands.
func TestSubcommands(t *testing.T) {
	sub := func(name string, words ...string) []string {
		e := commandNamed(name)
		for _, w := range words {
			e = subcommandOf(name, e, w)
		}
		var out []string
		for _, s := range Subcommands(e) {
			out = append(out, strings.Join(s.Subcommand, " "))
		}
		return out
	}
	if got := sub("gh", "issue"); !slices.Equal(got, []string{"issue close", "issue comment", "issue create", "issue edit", "issue list", "issue view"}) {
		t.Errorf("gh issue: %v", got)
	}
	if got := sub("gh"); !slices.Contains(got, "issue edit") || !slices.Contains(got, "api") {
		t.Errorf("gh: %v", got)
	}
	if got := sub("curl"); got != nil {
		t.Errorf("curl: %v", got)
	}
}

// TestLookupReadCommands: the commands of nnUNet's permissions are in the
// table; find reads the value of -exec as a program.
func TestLookupReadCommands(t *testing.T) {
	for _, n := range []string{"cat", "head", "tail", "wc"} {
		m := LookupCommand([]CommandWord{{Text: n, Known: true}})
		// transforms-input and digests-input say what the output is made of,
		// not what the command does: no capability
		caps := slices.DeleteFunc(slices.Clone(m.Entry.Traits), func(t CommandTrait) bool {
			return t == CommandTraitTransformsInput || t == CommandTraitDigestsInput
		})
		if m.Extent != MatchComplete || len(caps) != 0 {
			t.Errorf("%s: %v %+v", n, m.Extent, m.Entry)
		}
	}
	m := LookupCommand([]CommandWord{{Text: "find", Known: true}, {Text: "-exec", Known: true}, {Text: "sh", Known: true}})
	if m.Extent != MatchComplete || m.Readings[2] != ArgumentReadingProgram {
		t.Errorf("find -exec sh: %v %v", m.Extent, m.Readings)
	}
}

// TestLookupCommandIndex: where the command run past the wrappers is, known
// or not.
func TestLookupCommandIndex(t *testing.T) {
	for _, c := range []struct {
		words string
		want  int
	}{
		{"npm test", 0},
		{"sudo ./x.sh", 1},
		{"env A=1 timeout 5 ./x.sh", 4},
		{"sudo $X/y", 0}, // a word not known may be an option of sudo: it stops there
		{"sudo -u bob bash build.sh", 3},
		{"nohup", -1},
		{"no-such-command x", 0},
	} {
		if got := LookupCommand(known(c.words)).Command; got != c.want {
			t.Errorf("%s: %d, want %d", c.words, got, c.want)
		}
	}
}
