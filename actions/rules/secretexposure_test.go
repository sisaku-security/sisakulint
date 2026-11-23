package rules

import (
	"os"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// referencesOf are the references of the findings of secret-exposure, and
// the number of each finding's related locations.
func referencesOf(t *testing.T, files map[string]string) ([]string, []int) {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{SecretExposure}, files, exposureFacts{})
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %+v", rep.Errors)
	}
	var refs []string
	var related []int
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		refs = append(refs, f.Args.(SecretExposureAllSecrets).Reference)
		related = append(related, len(f.Related))
	}
	return refs, related
}

// TestSecretExposure: the reads of secrets the runs showed, and their
// places.
func TestSecretExposure(t *testing.T) {
	step := func(v string) map[string]string {
		return wfFile("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          X: " + v + "\n        run: \"true\"\n")
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"tojson", step("${{ toJSON(secrets) }}"), []string{"secrets"}},
		{"format", step("${{ secrets[format('A_{0}', 'B')] }}"), []string{"secrets[format('A_{0}', 'B')]"}},
		{"star", step("${{ join(secrets.*, ',') }}"), []string{"secrets.*"}},
		{"literal index", step("${{ secrets['A'] }}"), nil},
		{"two in a ${{ }}", step("${{ secrets[format('DEV_{0}', matrix.k)] || secrets[format('PROD_{0}', matrix.k)] }}"), []string{"secrets[format('DEV_{0}', matrix.k)]"}},
		{"named", step("${{ secrets.A }}"), nil},
		{"two in a job", wfFile("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      X: ${{ toJSON(secrets) }}\n    steps:\n      - run: echo ${{ secrets[matrix.n] }}\n"), []string{"secrets", "secrets[matrix.n]"}},
	} {
		if got, _ := referencesOf(t, c.files); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSecretExposureCalled: a workflow only a caller
// runs, by its callers.
func TestSecretExposureCalled(t *testing.T) {
	jobs := "jobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          X: ${{ toJSON(secrets) }}\n        run: \"true\"\n"
	called := "on:\n  workflow_call:\n" + jobs
	named := "on: push\njobs:\n  a:\n    uses: ./.github/workflows/called.yml\n    secrets:\n      A: ${{ secrets.A }}\n"
	inherit := "on: push\njobs:\n  a:\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n"
	for _, c := range []struct {
		name    string
		files   map[string]string
		want    []string
		related []int
	}{
		{"no caller", map[string]string{".github/workflows/called.yml": called}, []string{"secrets"}, []int{0}},
		{"named caller", map[string]string{".github/workflows/called.yml": called, ".github/workflows/ci.yml": named}, nil, nil},
		{"inherit caller", map[string]string{".github/workflows/called.yml": called, ".github/workflows/ci.yml": inherit}, []string{"secrets"}, []int{1}},
		{"push too", map[string]string{".github/workflows/called.yml": "on: [workflow_call, push]\n" + jobs, ".github/workflows/ci.yml": named}, []string{"secrets"}, []int{0}},
	} {
		got, related := referencesOf(t, c.files)
		if !slices.Equal(got, c.want) || !slices.Equal(related, c.related) {
			t.Errorf("%s: %q %v, want %q %v", c.name, got, related, c.want, c.related)
		}
	}
}

// TestSecretExposureUpstream: sisakulint's examples (17c2d82151a966e6e388a17619b060ae2919712e,
// script/actions/secretexposure{,-safe}.yaml). The vulnerable one has six
// jobs; bracket-notation reads secrets['GITHUB_TOKEN'], which names the
// secret: five findings. The safe one has none.
func TestSecretExposureUpstream(t *testing.T) {
	for _, c := range []struct {
		file string
		want int
	}{{"secretexposure.yaml", 5}, {"secretexposure-safe.yaml", 0}} {
		src, err := os.ReadFile("testdata/upstream/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := referencesOf(t, wfFile(string(src))); len(got) != c.want {
			t.Errorf("%s: %q, want %d", c.file, got, c.want)
		}
	}
}

// TestSecretExposureProbe: the workflows of the observed runs
// (testdata/observed/secret-exposure: the workflows of the runs, copied).
func TestSecretExposureProbe(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile("testdata/observed/" + p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// s1-secrets.yml: tojson, index-format, star, if-false; not none, named-a,
	// named-a-lower, index-literal, nor the json job
	got, _ := referencesOf(t, wfFile(read("secret-exposure/3/.github/workflows/s1-secrets.yml")))
	if want := []string{"secrets", "secrets[format('PROBE_{0}', 'A')]", "secrets.*", "secrets"}; !slices.Equal(got, want) {
		t.Errorf("s1-secrets.yml: %q, want %q", got, want)
	}
	// s3-callers.yml: called-tojson.yml, once, with its inherit caller; not called-plain.yml
	files := map[string]string{}
	for _, f := range []string{"s3-callers.yml", "called-tojson.yml", "called-plain.yml"} {
		files[".github/workflows/"+f] = read("secret-exposure/5/.github/workflows/" + f)
	}
	got, related := referencesOf(t, files)
	if !slices.Equal(got, []string{"secrets"}) || !slices.Equal(related, []int{1}) {
		t.Errorf("s3-callers.yml: %q %v", got, related)
	}
}
