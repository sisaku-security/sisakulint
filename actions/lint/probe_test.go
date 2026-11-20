package lint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The experiments on what GitHub's reader rejects, run as the repositories
// they were: a workflow GitHub rejected for a form the model checks is
// invalid, and one it took is read. Those it rejected for a form the model
// does not check (a ${{ }} with a context) are read.
func TestValidityProbes(t *testing.T) {
	invalid := map[string]bool{
		// IDs of steps and jobs, and calls of reusable workflows
		"v01-step-id-case.yml": true, "v02-job-id-case.yml": true, "v13-step-id-100.yml": true,
		"v14-step-id-reserved.yml": true, "v15-job-id-reserved.yml": true, "v16-step-id-form.yml": true,
		"v17-call-missing-input.yml": true, "v18-call-undefined-input.yml": true, "v19-call-type-bool.yml": true,
		"v20-call-type-num.yml": true, "v21-call-type-expr.yml": true, "v22-call-missing-secret.yml": true,
		"v23-call-undefined-secret.yml": true,
		// parallel groups, inputs and callable workflows
		"w01-parallel-dup-outer.yml": true, "w02-parallel-dup-inner.yml": true, "w03-parallel-dup-groups.yml": true,
		"w06-required-with-default.yml": true, "w08-bool-quoted.yml": true, "w09-num-quoted.yml": true,
		"w10-bool-yes.yml": true, "w11-not-callable.yml": true,
		// booleans and numbers
		"x01-bool-int-1.yml": true, "x02-bool-int-0.yml": true, "x03-num-bool.yml": true, "x05-bool-on.yml": true,
		// with and secrets with no value
		"y01-bare-with.yml": true, "y02-bare-secrets.yml": true, "y03-no-secrets-defined.yml": true,
	}
	for _, version := range []string{"validity-checks/4", "validity-checks/2", "validity-checks/1", "validity-checks/3"} {
		dir := filepath.Join("testdata", "observed", filepath.FromSlash(version))
		in, err := Enumerate(os.DirFS(dir))
		if err != nil {
			t.Fatal(err)
		}
		reg, err := newRegistry(nil, true)
		if err != nil {
			t.Fatal(err)
		}
		rep := Run(context.Background(), in, reg, mapResolver{})
		if len(rep.Inputs) == 0 {
			t.Fatalf("%s: no inputs", version)
		}
		for _, i := range rep.Inputs {
			want := InputStateRead
			if invalid[filepath.Base(i.Name.String())] {
				want = InputStateInvalid
			}
			if i.State != want {
				t.Errorf("%s %s: %s, want %s (diagnostics %+v)", version, i.Name, i.State, want, i.Diagnostics)
			}
		}
	}
}
