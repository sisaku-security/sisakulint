package ir

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

const uploadWF = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: true}\n      - run: echo\n"

func TestUploadProjection(t *testing.T) {
	x := newIR(t, uploadWF)
	us := x.allUploads()
	if len(us) != 1 {
		t.Fatalf("%d uploads", len(us))
	}
	u := us[0]
	cs := x.allLeftCredentials()
	if len(cs) != 1 || cs[0].file != analysis.CredentialFileGitConfig || cs[0].key.Path() != "jobs.a.steps[0]" || !cs[0].checkout {
		t.Errorf("left credentials %+v", cs)
	}
	if !slices.Equal(u.takenCredentials, []TakenCredential{{Index: 0, Hidden: true}}) || !u.downloadableDuringRun || u.tokenWrite != analysis.TokenWriteUnwritten {
		t.Errorf("%+v", u)
	}
	if u.key.Path() != "jobs.a.steps[1]" {
		t.Errorf("key %s", u.key)
	}
}

// TestPersistFalse: with none, with others, persist-credentials true,
// and an alias.
func TestPersistFalse(t *testing.T) {
	up := "      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: true}\n      - run: echo\n"
	pre := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
	for _, c := range []struct {
		name, checkout, want string // want: the checkout after the fix; "" for no fix
	}{
		{"no with", "      - uses: actions/checkout@v4\n", "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"},
		{"with", "      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n", "      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n"},
		{"true", "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: true\n", "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n"},
		{"alias", "      - &co\n        uses: actions/checkout@v4\n      - *co\n", ""},
	} {
		x := newIR(t, pre+c.checkout+up)
		cs := x.allLeftCredentials()
		if len(cs) == 0 {
			t.Errorf("%s: no exposure", c.name)
			continue
		}
		o := cs[len(cs)-1].persistCredentialsFalse(x.RuleAccess()) // the last: in alias, the step through *co
		if c.want == "" {
			if o.Fix != nil || o.NoFix == nil || o.NoFix.Reason != NoFixReasonForm {
				t.Errorf("%s: %+v", c.name, o)
			}
			continue
		}
		if o.Fix == nil {
			t.Errorf("%s: %+v", c.name, o.NoFix)
			continue
		}
		res, err := edit.Apply(x.tree, o.Fix.Edits)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(res.Tree.Bytes()); !strings.Contains(got, c.want) {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}

// TestPersistFalseOther: a credential of another step has no fix.
func TestPersistFalseOther(t *testing.T) {
	x := newIR(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: JamesIves/github-pages-deploy-action@v4\n        with: {folder: b}\n      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: true}\n      - run: echo\n")
	o := x.allLeftCredentials()[0].persistCredentialsFalse(x.RuleAccess())
	if o.Fix != nil || o.NoFix == nil || o.NoFix.Reason != NoFixReasonManual {
		t.Errorf("%+v", o)
	}
}

// TestPersistFalseAnchored: a step with an
// anchor is not edited, as its aliases, maybe in another job, would change
// with it.
func TestPersistFalseAnchored(t *testing.T) {
	x := newIR(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - &co\n        uses: actions/checkout@v4\n      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: true}\n      - run: echo\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - *co\n      - run: git push\n")
	o := x.allLeftCredentials()[0].persistCredentialsFalse(x.RuleAccess())
	if o.Fix != nil || o.NoFix == nil || o.NoFix.Reason != NoFixReasonForm {
		t.Errorf("%+v", o)
	}
}

// TestLeftCredentialsShared: a credential that three uploads take is one
// LeftCredential, which each upload names by its index.
func TestLeftCredentialsShared(t *testing.T) {
	up := "      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: true}\n"
	x := newIR(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"+up+up+up)
	if cs := x.allLeftCredentials(); len(cs) != 1 {
		t.Fatalf("%d left credentials", len(cs))
	}
	for i, u := range x.allUploads() {
		if !slices.Equal(u.takenCredentials, []TakenCredential{{Index: 0, Hidden: true}}) {
			t.Errorf("upload %d: %+v", i, u.takenCredentials)
		}
	}
}
