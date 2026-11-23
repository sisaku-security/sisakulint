package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

const (
	privateCond = `{"query":{"kind":"repo.public"},"eq":false}`
	pwJob       = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container:\n      image: a@" + digest + "\n      credentials:\n        username: u\n        password: %s\n    steps:\n      - run: echo\n"
)

// TestCredentials: the forms of
// the password, and repo.public true, false and not known.
func TestCredentials(t *testing.T) {
	for _, c := range []struct {
		name, password string
		public         *bool
		want           []string // kind, then certainty
		inc            int
	}{
		{"literal unknown", "hunter2", nil, []string{"credentials.private", "conditional", "credentials.public", "conditional"}, 0},
		{"literal public", "hunter2", ptr(true), []string{"credentials.public", "confirmed"}, 0},
		{"literal private", "hunter2", ptr(false), []string{"credentials.private", "confirmed"}, 0},
		{"dollar brace", "'${PW}'", ptr(true), []string{"credentials.public", "confirmed"}, 0},
		{"constant", "${{ 'hunter2' }}", ptr(true), []string{"credentials.public", "confirmed"}, 0},
		{"secret", "${{ secrets.REG }}", ptr(true), nil, 0},
		{"env", "${{ env.PW }}", ptr(true), nil, 1},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{Credentials}, wfFile(fmt.Sprintf(pwJob, c.password)), exposureFacts{public: c.public})
		var got []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got = append(got, f.Args.KindID().String(), certainty(f))
			if want := map[string]string{"credentials.public": publicCond, "credentials.private": privateCond}[f.Args.KindID().String()]; condJSON(t, f) != want {
				t.Errorf("%s: %s", c.name, condJSON(t, f))
			}
		}
		if !slices.Equal(got, c.want) || len(rep.FindingsWith(lint.CertaintyInconclusive)) != c.inc {
			t.Errorf("%s: %v %+v; want %v", c.name, got, rep.FindingsWith(lint.CertaintyInconclusive), c.want)
		}
	}
}

// TestCredentialsService: a service's password, named in the args.
func TestCredentialsService(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    services:\n      db:\n        image: postgres@" + digest + "\n        credentials: {username: u, password: hunter2}\n    steps:\n      - run: echo\n"
	rep, _, _ := checkRules(t, []lint.Rule{Credentials}, wfFile(src), exposureFacts{public: ptr(true)})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args != (CredentialsPublic{Container: "services.db"}) {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestCredentialsNone: no finding without a credential of a container.
func TestCredentialsNone(t *testing.T) {
	files := map[string]string{
		".github/workflows/w.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    container: node\n    steps:\n      - run: echo\n",
		".github/workflows/v.yml": "on: push\n",
		"action.yml":              "name: x\ndescription: x\nruns:\n  using: docker\n  image: Dockerfile\n",
	}
	rep, _, _ := checkRules(t, []lint.Rule{Credentials}, files, exposureFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
		t.Errorf("%+v %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// TestCredentialsRepo: the name of the repository given to lint is in the
// repo.public credentials asks.
func TestCredentialsRepo(t *testing.T) {
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(fmt.Sprintf(pwJob, "hunter2"))}})
	if err != nil {
		t.Fatal(err)
	}
	in.Repo, _ = facts.ParseRepo("o/r")
	reg, err := lint.NewRegistry([]lint.Rule{Credentials})
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(context.Background(), in, reg, facts.Assumptions())
	if len(rep.Facts) != 1 {
		t.Fatalf("%+v", rep.Facts)
	}
	if b, err := facts.EncodeQuery(rep.Facts[0].Query); err != nil || !strings.Contains(string(b), `"repo":"o/r"`) {
		t.Errorf("%s %v", b, err)
	}
}

func certainty(f lint.Finding) string {
	if f.Certainty == lint.CertaintyConfirmed {
		return "confirmed"
	}
	return "conditional"
}
