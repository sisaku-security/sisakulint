package workflow

import (
	"strings"
	"testing"
)

func TestUses(t *testing.T) {
	sha := strings.Repeat("0123456789", 4)
	digest := "sha256:" + strings.Repeat("ab", 32)
	for _, tt := range []struct {
		uses string
		kind UsesKind
		// the pieces that are there, as "name=text"
		want []string
	}{
		{"actions/checkout@v4", UsesRemote, []string{"owner=actions", "repo=checkout", "ref=v4"}},
		{"actions/checkout@" + sha, UsesRemote, []string{"owner=actions", "repo=checkout", "ref=" + sha}},
		// an action in a directory of a repository
		{"owner/repo/path/to@ref", UsesRemote, []string{"owner=owner", "repo=repo", "path=path/to", "ref=ref"}},
		{"./local", UsesLocal, []string{"path=./local"}},
		{"./.github/actions/x", UsesLocal, []string{"path=./.github/actions/x"}},
		{"docker://alpine:3.19", UsesDocker, []string{"image=alpine", "tag=3.19"}},
		// an image pinned to a digest
		{"docker://alpine@" + digest, UsesDocker, []string{"image=alpine", "digest=" + digest}},
		{"docker://ghcr.io/o/i:tag", UsesDocker, []string{"image=ghcr.io/o/i", "tag=tag"}},
		{"docker://localhost:5000/img", UsesDocker, []string{"image=localhost:5000/img"}},
		{"docker://localhost:5000/img:1", UsesDocker, []string{"image=localhost:5000/img", "tag=1"}},
		// runner PipelineConstants.TryParseSelfRepository: the workflow's own
		// repository at its commit; home-assistant/core uses it.
		{"$/.github/actions/x", UsesSelf, []string{"path=.github/actions/x"}},
		{"$//actions/x", UsesSelf, []string{"path=actions/x"}},
		{"$/", UsesSelf, nil},
		{"$/foo@v1", UsesInvalid, nil},
		{"actions/checkout", UsesInvalid, nil},
		{"@v4", UsesInvalid, nil},
		{"owner@ref", UsesInvalid, nil},
		{"owner/@ref", UsesInvalid, nil},
		{"owner/repo@", UsesInvalid, nil},
		{"docker://", UsesInvalid, nil},
	} {
		src := "steps:\n  - uses: '" + tt.uses + "'\n"
		f, diags := readSteps(t, src)
		if tt.kind == UsesInvalid {
			wantCodes(t, tt.uses, diags, InvalidValue)
		} else {
			wantCodes(t, tt.uses, diags)
		}
		u := f.Value.Items[0].Uses.Value
		if u.Kind != tt.kind {
			t.Errorf("%s: kind %v, want %v", tt.uses, u.Kind, tt.kind)
			continue
		}
		got := map[string]Piece{"owner": u.Owner, "repo": u.Repo, "path": u.Path, "ref": u.Ref, "image": u.Image, "tag": u.Tag, "digest": u.Digest}
		want := map[string]string{}
		for _, w := range tt.want {
			k, v, _ := strings.Cut(w, "=")
			want[k] = v
		}
		for name, p := range got {
			if p.Text != want[name] {
				t.Errorf("%s: %s = %q, want %q", tt.uses, name, p.Text, want[name])
			}
			if p.Text == "" {
				continue
			}
			// Each piece maps back to the input.
			sp, exact := u.Source(p.Span)
			if !exact || text(src, sp) != p.Text {
				t.Errorf("%s: %s maps to %q", tt.uses, name, text(src, sp))
			}
		}
	}
}

// TestFoldedUses: ${{ 'x' }} folds into x, whose bytes are the literal's in
// the input, so the pieces of x are made in the value, as for any uses. A
// literal with an escaped quote (a doubled single quote) is not the value's
// bytes one for one: it gets no pieces, and Folded is UsesInvalid.
func TestFoldedUses(t *testing.T) {
	for _, tt := range []struct {
		src    string // the scalar as written
		folded UsesKind
		want   []string
	}{
		{`${{ 'actions/checkout@v4' }}`, UsesRemote, []string{"owner=actions", "repo=checkout", "ref=v4"}},
		{`"${{ 'owner/repo/sub@v1' }}"`, UsesRemote, []string{"owner=owner", "repo=repo", "path=sub", "ref=v1"}},
		{`${{ './local' }}`, UsesLocal, []string{"path=./local"}},
		{`${{ 'docker://alpine:3' }}`, UsesDocker, []string{"image=alpine", "tag=3"}},
		{`${{ 'nope' }}`, UsesInvalid, nil},
		{`${{ 'it''s/repo@v1' }}`, UsesInvalid, nil},
	} {
		src := "steps:\n  - uses: " + tt.src + "\n"
		f, _ := readSteps(t, src)
		u := f.Value.Items[0].Uses.Value
		if u.Kind != UsesFolded || u.Folded != tt.folded {
			t.Errorf("%s: kind %v, folded %v; want UsesFolded, %v", tt.src, u.Kind, u.Folded, tt.folded)
			continue
		}
		got := map[string]Piece{"owner": u.Owner, "repo": u.Repo, "path": u.Path, "ref": u.Ref, "image": u.Image, "tag": u.Tag, "digest": u.Digest}
		want := map[string]string{}
		for _, w := range tt.want {
			k, v, _ := strings.Cut(w, "=")
			want[k] = v
		}
		for name, p := range got {
			if p.Text != want[name] {
				t.Errorf("%s: %s = %q, want %q", tt.src, name, p.Text, want[name])
			}
			if p.Text == "" {
				continue
			}
			if sp, exact := u.Source(p.Span); !exact || text(src, sp) != p.Text {
				t.Errorf("%s: %s maps to %q", tt.src, name, text(src, sp))
			}
		}
	}
}

// The uses of a job that calls a reusable workflow.
func TestUsesOfJob(t *testing.T) {
	for _, tt := range []struct {
		uses string
		kind UsesKind
	}{
		{"./.github/workflows/x.yml", UsesLocal},
		{"o/r/.github/workflows/x.yml@v1", UsesRemote},
		{"$/.github/workflows/x.yml", UsesSelf},
	} {
		src := "steps:\n  - uses: " + tt.uses + "\n"
		f, _ := readSteps(t, src)
		u := f.Value.Items[0].Uses.Value
		if u.Kind != tt.kind {
			t.Errorf("%s: %v", tt.uses, u.Kind)
		}
	}
	// step-uses has no context.
	oneStep(t, "  - uses: ${{ x }}\n", ExprNotAllowed)
}

// TestDockerTagAndDigest: a tag before a digest.
func TestDockerTagAndDigest(t *testing.T) {
	d := "sha256:" + "ab"
	src := "steps:\n  - uses: docker://img:1@" + d + "\n"
	f, _ := readSteps(t, src)
	u := f.Value.Items[0].Uses.Value
	if u.Image.Text != "img" || u.Tag.Text != "1" || u.Digest.Text != d {
		t.Errorf("image %q tag %q digest %q", u.Image.Text, u.Tag.Text, u.Digest.Text)
	}
}

// actionText is a as owner/repo[/path]@ref.
func actionText(a UsesAction) string {
	s := a.Owner + "/" + a.Repo
	if !a.Path.IsZero() {
		s += "/" + a.Path.String()
	}
	return s + "@" + a.Ref
}

// TestUsesReading: a step's uses as GitHub reads it: the runner drops
// empty parts of owner/repo/path, reads a backslash of the path as /, and
// resolves . and .. from the runner's directory of actions
// (_actions/<owner>/<repo>/<ref>); ./ and $/ resolve . and .. too.
func TestUsesReading(t *testing.T) {
	sha := strings.Repeat("0123456789", 4)
	for _, tt := range []struct {
		uses       string
		kind       UsesKind
		runs       []string // Actions, as actionText
		normalized string   // Normalized; "" when it is false
		outside    UsesOutside
		target     string
		local      string // LocalPath, with HasLocalPath; "-" for none
	}{
		{"actions/checkout@v4", UsesRemote, []string{"actions/checkout@v4"}, "actions/checkout@v4", OutsideNone, "", "-"},
		// GitHub drops empty parts
		{"/o/r/x@" + sha, UsesRemote, []string{"o/r/x@" + sha}, "o/r/x@" + sha, OutsideNone, "", "-"},
		{"o//r/x@" + sha, UsesRemote, []string{"o/r/x@" + sha}, "o/r/x@" + sha, OutsideNone, "", "-"},
		{"o/r/x/@" + sha, UsesRemote, []string{"o/r/x@" + sha}, "o/r/x@" + sha, OutsideNone, "", "-"},
		{"o/r//x@" + sha, UsesRemote, []string{"o/r/x@" + sha}, "o/r/x@" + sha, OutsideNone, "", "-"},
		{"actions/github-script/@v7", UsesRemote, []string{"actions/github-script@v7"}, "actions/github-script@v7", OutsideNone, "", "-"},
		// . and .. resolve as text
		{"actions/github-script/.@v7", UsesRemote, []string{"actions/github-script@v7"}, "actions/github-script@v7", OutsideNone, "", "-"},
		{"actions/github-script/x/..@v7", UsesRemote, []string{"actions/github-script@v7"}, "actions/github-script@v7", OutsideNone, "", "-"},
		{"o/r/acts/b/../a@v1", UsesRemote, []string{"o/r/acts/a@v1"}, "o/r/acts/a@v1", OutsideNone, "", "-"},
		// a backslash of the path is a separator
		{`o/r/a\b@v1`, UsesRemote, []string{"o/r/a/b@v1"}, "o/r/a/b@v1", OutsideNone, "", "-"},
		// a backslash before the end of the repository is refused
		{`o\r/x@v1`, UsesInvalid, nil, "", OutsideNone, "", "-"},
		// back under the ref's own directory
		{"o/r/../main/x@main", UsesRemote, []string{"o/r/x@main"}, "o/r/x@main", OutsideNone, "", "-"},
		// above the root, into another ref's directory
		{"o/r/../probe/obfuscation/acts/b@" + sha, UsesRemote, []string{
			"o/r/obfuscation/acts/b@probe", "o/r/acts/b@probe/obfuscation", "o/r/b@probe/obfuscation/acts", "o/r@probe/obfuscation/acts/b",
		}, "", OutsideRepository, "o/r/probe/obfuscation/acts/b", "-"},
		// the directory of the repository, which has no action
		{"o/r/..@v1", UsesRemote, nil, "", OutsideRepository, "", "-"},
		// above the runner's directory of actions
		{"o/r/../../../../x/y/z@v1", UsesRemote, nil, "", OutsideRepository, "", "-"},
		// local paths with a . part, an empty part or a .. part
		{"./acts/./a", UsesLocal, nil, "./acts/a", OutsideNone, "", "acts/a"},
		{"./acts//a", UsesLocal, nil, "./acts/a", OutsideNone, "", "acts/a"},
		{"./acts/b/../a", UsesLocal, nil, "./acts/a", OutsideNone, "", "acts/a"},
		{"./acts/a", UsesLocal, nil, "./acts/a", OutsideNone, "", "acts/a"},
		{"./", UsesLocal, nil, "./", OutsideNone, "", ""},
		{"./../x/a", UsesLocal, nil, "", OutsideWorkspace, "", "-"},
		// the same parts after $/
		{"$/acts/./a", UsesSelf, nil, "$/acts/a", OutsideNone, "", "acts/a"},
		{"$/acts/b/../a", UsesSelf, nil, "$/acts/a", OutsideNone, "", "acts/a"},
		{"$/acts/a", UsesSelf, nil, "$/acts/a", OutsideNone, "", "acts/a"},
		// $/ is in _actions/<owner>/<repo>/<commit>, whose names the input does not tell
		{"$/../../../actions/github-script/v7", UsesSelf, []string{"actions/github-script@v7"}, "", OutsideRepository, "actions/github-script/v7", "-"},
		{"$/../other/x", UsesSelf, nil, "", OutsideRepository, "", "-"},
		// white space is a character of a path
		{"o/r/a b@v1", UsesRemote, []string{"o/r/a b@v1"}, "o/r/a b@v1", OutsideNone, "", "-"},
	} {
		src := "steps:\n  - uses: '" + tt.uses + "'\n"
		f, diags := readSteps(t, src)
		if tt.kind == UsesInvalid {
			wantCodes(t, tt.uses, diags, InvalidValue)
		} else {
			wantCodes(t, tt.uses, diags)
		}
		u := f.Value.Items[0].Uses.Value
		if u.Kind != tt.kind {
			t.Errorf("%s: kind %v, want %v", tt.uses, u.Kind, tt.kind)
			continue
		}
		var runs []string
		for _, a := range u.Actions() {
			runs = append(runs, actionText(a))
		}
		if strings.Join(runs, " ") != strings.Join(tt.runs, " ") {
			t.Errorf("%s: actions %q, want %q", tt.uses, runs, tt.runs)
		}
		if n, ok := u.Normalized(); ok != (tt.normalized != "") || n != tt.normalized {
			t.Errorf("%s: normalized %q %v, want %q", tt.uses, n, ok, tt.normalized)
		}
		if u.Outside != tt.outside || u.Target != tt.target {
			t.Errorf("%s: outside %v %q, want %v %q", tt.uses, u.Outside, u.Target, tt.outside, tt.target)
		}
		local := "-"
		if u.HasLocalPath {
			local = u.LocalPath.String()
		}
		if local != tt.local {
			t.Errorf("%s: local path %q, want %q", tt.uses, local, tt.local)
		}
		// the pieces still map back to what is written
		for name, p := range map[string]Piece{"owner": u.Owner, "repo": u.Repo, "path": u.Path, "ref": u.Ref} {
			if p.Text == "" {
				continue
			}
			if sp, exact := u.Source(p.Span); !exact || text(src, sp) != p.Text {
				t.Errorf("%s: %s maps to %q", tt.uses, name, text(src, sp))
			}
		}
	}
}

// TestOutsideMatched: a uses above the root of its repository runs what
// another uses of the same steps downloads; with none, every way
// to split the rest into a ref and a path is a reading.
func TestOutsideMatched(t *testing.T) {
	sha := strings.Repeat("0123456789", 4)
	src := "steps:\n  - uses: o/r/acts/b@probe/obfuscation\n  - uses: o/r/../probe/obfuscation/acts/b@" + sha + "\n" +
		"  - uses: o/r/acts/comp@" + sha + "\n  - uses: o/r/../../../actions/github-script/v7@" + sha + "\n"
	f, diags := readSteps(t, src)
	wantCodes(t, src, diags)
	s11, e4 := f.Value.Items[1].Uses.Value, f.Value.Items[3].Uses.Value
	if !s11.Matched || len(s11.Actions()) != 1 || actionText(s11.Actions()[0]) != "o/r/acts/b@probe/obfuscation" {
		t.Errorf("a ref with a slash: matched %v, actions %v", s11.Matched, s11.Actions())
	}
	if e4.Matched || len(e4.Actions()) != 1 || actionText(e4.Actions()[0]) != "actions/github-script@v7" {
		t.Errorf("github-script above the root: matched %v, actions %v", e4.Matched, e4.Actions())
	}
}

// TestFoldedUsesReading: a folded literal is read as what it folds to.
func TestFoldedUsesReading(t *testing.T) {
	f, _ := readSteps(t, "steps:\n  - uses: ${{ 'o/r/./x@v1' }}\n")
	u := f.Value.Items[0].Uses.Value
	if a := u.Actions(); len(a) != 1 || actionText(a[0]) != "o/r/x@v1" {
		t.Errorf("folded: actions %v", a)
	}
}
