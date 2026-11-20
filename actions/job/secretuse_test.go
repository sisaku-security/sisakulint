package job

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// readsOf are the texts of the reads of the secrets context of src.
func readsOf(t *testing.T, src string) []string {
	t.Helper()
	var out []string
	for _, r := range SecretsContextReads(parse(t, src)) {
		out = append(out, r.Text)
	}
	return out
}

// TestSecretsContextReads: the reads that name no secret, as GitHub sends
// every secret for, and those it does not.
func TestSecretsContextReads(t *testing.T) {
	step := func(v string) string {
		return "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - env:\n          X: " + v + "\n        run: \"true\"\n"
	}
	for _, c := range []struct {
		src  string
		want []string
	}{
		{step("${{ toJSON(secrets) }}"), []string{"secrets"}},
		{step("${{ secrets[format('A_{0}', matrix.e)] }}"), []string{"secrets[format('A_{0}', matrix.e)]"}},
		{step("${{ secrets[env.N] }}"), []string{"secrets[env.N]"}},
		{step("${{ join(secrets.*, ',') }}"), []string{"secrets.*"}},
		{step("${{ format('{0}', secrets) }}"), []string{"secrets"}},
		// one read for a ${{ }}, the first of its references
		{step("${{ secrets[format('DEV_{0}', matrix.k)] || secrets[format('PROD_{0}', matrix.k)] }}"), []string{"secrets[format('DEV_{0}', matrix.k)]"}},
		{step("${{ toJSON(secrets) != toJSON(secrets) }}"), []string{"secrets"}},
		{step("${{ secrets['PROBE_A'] }}"), nil},
		{step("${{ secrets.probe_a }}"), nil},
		{step("${{ toJSON(secrets.A) }}"), nil},
		{step("${{ github.token }}"), nil},
		// inside an index of another context, as Secrets.All reads
		{step("${{ env[toJSON(secrets)] }}"), []string{"secrets"}},
		{step("${{ matrix[secrets[matrix.k]] }}"), []string{"secrets[matrix.k]"}},
		// the step's if is evaluated after GitHub sends them (e1 if-false)
		{"on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - if: false\n        env:\n          X: ${{ toJSON(secrets) }}\n        run: \"true\"\n", []string{"secrets"}},
		// the env of the workflow, once, for a job that is not a call
		{"on: push\nenv:\n  X: ${{ toJSON(secrets) }}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n  b:\n    runs-on: x\n    steps:\n      - run: echo\n", []string{"secrets"}},
		// and none for jobs that only call
		{"on: push\nenv:\n  X: ${{ toJSON(secrets) }}\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n", nil},
		// where a job reads the secrets: the name, the run and the with of a step,
		// the outputs of a job, and the secrets of a job that calls
		{"on: push\njobs:\n  a:\n    runs-on: x\n    outputs:\n      o: ${{ toJSON(secrets) }}\n    steps:\n      - name: ${{ secrets[matrix.n] }}\n        run: echo ${{ toJSON(secrets) }}\n      - uses: o/a@v1\n        with:\n          s: ${{ toJSON(secrets) }}\n  b:\n    uses: ./.github/workflows/c.yml\n    secrets:\n      all: ${{ toJSON(secrets) }}\n", []string{"secrets", "secrets[matrix.n]", "secrets", "secrets", "secrets"}},
		// the env and the credentials of the job's container and of its
		// services, and a step's working-directory, timeout-minutes and
		// continue-on-error, where GitHub sends every secret too
		{"on: push\njobs:\n  a:\n    runs-on: x\n    container:\n      image: i\n      credentials:\n        username: ${{ toJSON(secrets) }}\n        password: p\n      env:\n        A: ${{ toJSON(secrets) }}\n    services:\n      s:\n        image: i\n        env:\n          B: ${{ toJSON(secrets) }}\n    steps:\n      - run: \"true\"\n        working-directory: ${{ toJSON(secrets) }}\n        timeout-minutes: ${{ toJSON(secrets) }}\n        continue-on-error: ${{ toJSON(secrets) }}\n", []string{"secrets", "secrets", "secrets", "secrets", "secrets", "secrets"}},
	} {
		if got := readsOf(t, c.src); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.src, got, c.want)
		}
	}
}

// partsOf are the names of the secrets of each SecretPart of src,
// joined by a comma.
func partsOf(t *testing.T, src string) []string {
	t.Helper()
	var out []string
	for _, p := range SecretParts(parse(t, src)) {
		out = append(out, strings.Join(p.Secrets, ","))
	}
	return out
}

// TestSecretParts: a value taken out of a secret by fromJSON, which the
// runner does not mask, where the runner prints it.
func TestSecretParts(t *testing.T) {
	step := func(v string) string {
		return "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - env:\n          X: \"" + v + "\"\n        run: \"true\"\n"
	}
	for _, c := range []struct {
		src  string
		want []string
	}{
		{step("${{ fromJSON(secrets.J).pass }}"), []string{"J"}},
		{step("${{ fromJson(secrets.J)['pass'] }}"), []string{"J"}},
		{step("${{ fromJSON(secrets.J).db.user }}"), []string{"J"}},
		{step("${{ fromJSON(secrets.J).list[0] }}"), []string{"J"}},
		{step("${{ join(fromJSON(secrets.J).list, ',') }}"), []string{"J"}},
		{step("${{ toJSON(fromJSON(secrets.J)) }}"), []string{"J"}},
		{step("${{ case(true, fromJSON(secrets.J).pass, 'none') }}"), []string{"J"}},
		{step("${{ fromJSON(secrets.J).missing || fromJSON(secrets.K).user }}"), []string{"J,K"}},
		{step("u=${{ format('{0}', fromJSON(secrets.J).user) }}"), []string{"J"}},
		{step("${{ fromJSON(secrets[matrix.n]).pass }}"), []string{"*"}},
		{step("${{ fromJSON(secrets.J).user == 'x' }}"), nil},
		{step("${{ contains(fromJSON(secrets.J).user, 'x') }}"), nil},
		{step("${{ !fromJSON(secrets.J).ok }}"), nil},
		{step("o=${{ fromJSON(secrets.J) }}"), nil},
		{step("${{ fromJSON(toJSON(secrets)).J }}"), nil},
		{step("${{ secrets.J }}"), nil},
		{step("${{ fromJSON(env.J).pass }}"), nil}, // no J in the env
		{step("${{ case(fromJSON(secrets.J).on, 'a', 'b') }}"), nil},
		// && gives a falsy operand or its last one (the runner's And.cs)
		{step("${{ fromJSON(secrets.J).enabled && 'on' || 'off' }}"), nil},
		{step("${{ fromJSON(secrets.J).enabled && 'on' }}"), nil},
		{step("${{ github.event_name == 'push' && fromJSON(secrets.J).p }}"), []string{"J"}},
		// format and .* make an object or an array a string, Object or
		// Array; join writes its separator
		{step("${{ toJSON(format('{0}', fromJSON(secrets.J))) }}"), nil},
		{step("${{ format('{0}', fromJSON(secrets.J)).x }}"), nil},
		{step("o=${{ fromJSON(secrets.J).* }}"), nil},
		{step("${{ join(fromJSON(secrets.J).*, ',') }}"), []string{"J"}},
		{step("${{ join(github.event.list, fromJSON(secrets.J).sep) }}"), []string{"J"}},
		// the places the runner prints: the env of the workflow and of a
		// job, and the name, the run and the with of a step
		{"on: push\nenv:\n  W: ${{ fromJSON(secrets.J).a }}\njobs:\n  a:\n    runs-on: x\n    env:\n      B: ${{ fromJSON(secrets.J).b }}\n    steps:\n      - name: n ${{ fromJSON(secrets.J).c }}\n        run: echo ${{ fromJSON(secrets.J).d }}\n      - uses: o/a@v1\n        with:\n          v: ${{ fromJSON(secrets.J).e }}\n", []string{"J", "J", "J", "J", "J"}},
		// the env and the username of the credentials of the job's
		// container and of its services, which the runner prints at the
		// start of the job; not the password, which it does not
		{"on: push\njobs:\n  a:\n    runs-on: x\n    container:\n      image: i\n      credentials:\n        username: ${{ fromJSON(secrets.J).n }}\n        password: ${{ fromJSON(secrets.J).p }}\n      env:\n        U: ${{ fromJSON(secrets.J).u }}\n    services:\n      s:\n        image: i\n        credentials:\n          username: ${{ fromJSON(secrets.K).n }}\n          password: ${{ fromJSON(secrets.K).p }}\n        env:\n          V: ${{ fromJSON(secrets.K).v }}\n    steps:\n      - run: echo\n", []string{"J", "J", "K", "K"}},
		{"on: push\njobs:\n  a:\n    runs-on: x\n    container:\n      image: i\n      env: ${{ fromJSON(secrets.J) }}\n    steps:\n      - run: echo\n", nil},
		// whole-map: credentials as one ${{ }}
		{"on: push\njobs:\n  a:\n    runs-on: x\n    container:\n      image: i\n      credentials: ${{ fromJSON(secrets.R) }}\n    steps:\n      - run: echo\n", nil},
		// no docker login without a password: the username is not printed
		{"on: push\njobs:\n  a:\n    runs-on: x\n    container:\n      image: i\n      credentials:\n        username: ${{ fromJSON(secrets.J).n }}\n    steps:\n      - run: echo\n", nil},
		// not the outputs of a job, nor what a job that calls passes
		{"on: push\njobs:\n  a:\n    runs-on: x\n    outputs:\n      o: ${{ fromJSON(secrets.J).a }}\n    steps:\n      - run: echo\n  b:\n    uses: ./.github/workflows/c.yml\n    with:\n      v: ${{ fromJSON(secrets.J).b }}\n    secrets:\n      s: ${{ fromJSON(secrets.J).c }}\n", nil},
	} {
		if got := partsOf(t, c.src); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.src, got, c.want)
		}
	}
}

// TestSecretPartsEnv: env.<name> is the value of the variable of the env
// the expression sees, read in the order the runner evaluates the env.
func TestSecretPartsEnv(t *testing.T) {
	// the env of the workflow, of the job and of the step, and a run
	wf := func(wenv, jenv, senv, run string) string {
		return "on: push\nenv:\n  " + wenv + "\njobs:\n  a:\n    runs-on: x\n    env:\n      " + jenv + "\n    steps:\n      - env:\n          " + senv + "\n        run: \"" + run + "\"\n"
	}
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"job env", wf("N: n", "DB: ${{ secrets.DB }}", "P: ${{ fromJSON(env.DB).pass }}", "true"), []string{"DB"}},
		{"workflow env", wf("DB: ${{ secrets.DB }}", "N: n", "P: ${{ fromJSON(env.DB).pass }}", "true"), []string{"DB"}},
		{"index", wf("N: n", "DB: ${{ secrets.DB }}", "P: ${{ fromJSON(env['DB'])['pass'] }}", "true"), []string{"DB"}},
		{"step env in the run", wf("N: n", "N: n", "DB: ${{ secrets.DB }}", "echo ${{ fromJSON(env.DB).pass }}"), []string{"DB"}},
		// the env of a step is evaluated with the env of the job only
		{"step env in the step env", wf("N: n", "N: n", "DB: ${{ secrets.DB }}\n          P: ${{ fromJSON(env.DB).pass }}", "true"), nil},
		// the nearest level's variable of a name
		{"step over job", wf("N: n", "DB: ${{ secrets.DB }}", "DB: plain", "echo ${{ fromJSON(env.DB).pass }}"), nil},
		{"job over workflow", wf("DB: ${{ secrets.DB }}", "DB: ${{ secrets.OTHER }}", "P: ${{ fromJSON(env.DB).pass }}", "true"), []string{"OTHER"}},
		// a variable read with the levels above its own
		{"through env", wf("N: n", "DB: ${{ secrets.DB }}", "C: ${{ env.DB }}", "echo ${{ fromJSON(env.C).pass }}"), []string{"DB"}},
		// a name in its own case, as on Linux and macOS
		{"case", wf("N: n", "DB: ${{ secrets.DB }}", "P: ${{ fromJSON(env.db).pass }}", "true"), nil},
		// in any case on Windows
		{"case on Windows", strings.Replace(wf("N: n", "DB: ${{ secrets.DB }}", "P: ${{ fromJSON(env.db).pass }}", "true"), "runs-on: x", "runs-on: windows-latest", 1), []string{"DB"}},
		{"case on Windows, nearest", strings.Replace(wf("N: n", "db: ${{ secrets.DB }}", "DB: plain", "echo ${{ fromJSON(env.Db).pass }}"), "runs-on: x", "runs-on: windows-latest", 1), nil},
		{"string property", wf("N: n", "DB: ${{ secrets.DB }}", "P: ${{ env.DB.pass }}", "true"), nil},
		{"whole secret", wf("N: n", "DB: ${{ secrets.DB }}", "P: ${{ env.DB }}", "true"), nil},
		{"literal", wf("N: n", "DB: '{\\\"pass\\\": 1}'", "P: ${{ fromJSON(env.DB).pass }}", "true"), nil},
		// a value taken out of a secret in a variable, written again where
		// the runner prints it
		{"part in env", wf("N: n", "P: ${{ fromJSON(secrets.DB).pass }}", "Q: ${{ env.P }}", "true"), []string{"DB", "DB"}},
		{"toJSON(env)", wf("N: n", "P: ${{ fromJSON(secrets.DB).pass }}", "Q: n", "echo ${{ toJSON(env) }}"), []string{"DB", "DB"}},
		{"env star", wf("N: n", "P: ${{ fromJSON(secrets.DB).pass }}", "Q: n", "echo ${{ env.* }}"), []string{"DB"}},
		{"join(env.*)", wf("N: n", "P: ${{ fromJSON(secrets.DB).pass }}", "Q: n", "echo ${{ join(env.*, ',') }}"), []string{"DB", "DB"}},
		// an object written in a variable is Object
		{"object in env", wf("N: n", "O: ${{ fromJSON(secrets.DB) }}", "P: ${{ env.O.pass }}", "true"), nil},
		{"context JSON", wf("N: n", "S: ${{ toJSON(secrets) }}", "P: ${{ fromJSON(fromJSON(env.S).DB).pass }}", "true"), []string{"*"}},
		// GitHub allows no env context in the env of a job
		{"env in job env", wf("DB: ${{ secrets.DB }}", "P: ${{ fromJSON(env.DB).pass }}", "N: n", "true"), nil},
		// the env of the job's container: the job's and the workflow's
		{"container", "on: push\njobs:\n  a:\n    runs-on: x\n    env:\n      DB: ${{ secrets.DB }}\n    container:\n      image: i\n      env:\n        P: ${{ fromJSON(env.DB).pass }}\n    steps:\n      - run: echo\n", []string{"DB"}},
	} {
		if got := partsOf(t, c.src); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSecretPartsNeeds: a value taken out of a secret in an output of a
// job, which the runner keeps when the output has no masked value, and a
// later job that reads the output with needs prints.
func TestSecretPartsNeeds(t *testing.T) {
	const read = "  r:\n    runs-on: x\n    outputs:\n      p: %s\n    steps:\n      - run: echo\n"
	const print = "  print:\n    needs: r\n    runs-on: x\n    steps:\n      - run: echo '%s'\n"
	wf := func(output, ref string) string {
		return "on: push\njobs:\n" + fmt.Sprintf(read, output) + fmt.Sprintf(print, ref)
	}
	for _, c := range []struct {
		name, src string
		parts     []string
		via       []string
	}{
		{"one", wf("${{ fromJSON(secrets.DB).pass }}", "${{ needs.r.outputs.p }}"), []string{"DB"}, []string{"r.p"}},
		{"in a string", wf("pre-${{ fromJSON(secrets.DB).pass }}", "${{ needs.r.outputs.p }}"), []string{"DB"}, []string{"r.p"}},
		{"upper", wf("${{ fromJSON(secrets.DB).pass }}", "${{ NEEDS.R.OUTPUTS.P }}"), []string{"DB"}, []string{"r.p"}},
		{"outputs whole", wf("${{ fromJSON(secrets.DB).pass }}", "${{ toJSON(needs.r.outputs) }}"), []string{"DB"}, []string{"r.p"}},
		{"needs whole", wf("${{ fromJSON(secrets.DB).pass }}", "${{ toJSON(needs) }}"), []string{"DB"}, []string{"r.p"}},
		{"index", wf("${{ fromJSON(secrets.DB).pass }}", "${{ needs.r.outputs[matrix.o] }}"), []string{"DB"}, []string{"r.p"}},
		{"compared", wf("${{ fromJSON(secrets.DB).pass }}", "${{ needs.r.outputs.p == 'x' }}"), nil, nil},
		{"whole secret", wf("${{ secrets.DB }}", "${{ needs.r.outputs.p }}"), nil, nil},
		{"with a whole secret", wf("${{ secrets.A }}-${{ fromJSON(secrets.DB).pass }}", "${{ needs.r.outputs.p }}"), nil, nil},
		{"with the context", wf("${{ format('{0}{1}', toJSON(secrets), fromJSON(secrets.DB).pass) }}", "${{ needs.r.outputs.p }}"), nil, nil},
		// case and || give one value: a whole secret in some runs only
		{"case", wf("${{ case(github.ref == 'x', secrets.A, fromJSON(secrets.DB).pass) }}", "${{ needs.r.outputs.p }}"), []string{"A,DB"}, []string{"r.p"}},
		{"or", wf("${{ fromJSON(secrets.DB).pass || secrets.A }}", "${{ needs.r.outputs.p }}"), []string{"DB,A"}, []string{"r.p"}},
		{"case both", wf("${{ case(github.ref == 'x', secrets.A, secrets.B) }}-${{ fromJSON(secrets.DB).pass }}", "${{ needs.r.outputs.p }}"), nil, nil},
		{"object", wf("${{ fromJSON(secrets.DB) }}", "${{ needs.r.outputs.p }}"), nil, nil},
		{"not needed", "on: push\njobs:\n" + fmt.Sprintf(read, "${{ fromJSON(secrets.DB).pass }}") + "  print:\n    runs-on: x\n    steps:\n      - run: echo '${{ needs.r.outputs.p }}'\n", nil, nil},
		{"if", "on: push\njobs:\n" + fmt.Sprintf(read, "${{ fromJSON(secrets.DB).pass }}") + "  print:\n    needs: r\n    if: needs.r.outputs.p == 'x'\n    runs-on: x\n    steps:\n      - run: echo\n", nil, nil},
		{"two steps", "on: push\njobs:\n" + fmt.Sprintf(read, "${{ fromJSON(secrets.DB).pass }}") +
			"  m:\n    needs: r\n    runs-on: x\n    outputs:\n      q: ${{ needs.r.outputs.p }}\n    steps:\n      - run: echo\n" +
			"  print:\n    needs: m\n    runs-on: x\n    env:\n      Q: ${{ needs.m.outputs.q }}\n    steps:\n      - run: echo\n", []string{"DB"}, []string{"m.q", "r.p"}},
		{"diamond", "on: push\njobs:\n  a:\n    runs-on: x\n    outputs:\n      x: ${{ fromJSON(secrets.DB).pass }}\n      y: ${{ secrets.A }}\n    steps:\n      - run: echo\n" +
			"  b:\n    needs: a\n    runs-on: x\n    outputs:\n      z: ${{ needs.a.outputs.x }}\n    steps:\n      - run: echo\n" +
			"  c:\n    needs: [a, b]\n    runs-on: x\n    steps:\n      - run: echo '${{ needs.a.outputs.y }}' '${{ needs.b.outputs.z }}'\n", []string{"DB"}, []string{"b.z", "a.x"}},
		// an output read once and kept, for a second job and a second path
		{"two readers", "on: push\njobs:\n" + fmt.Sprintf(read, "${{ fromJSON(secrets.DB).pass }}") + fmt.Sprintf(print, "${{ needs.r.outputs.p }}") +
			"  print2:\n    needs: r\n    runs-on: x\n    steps:\n      - run: echo '${{ needs.r.outputs.p }}'\n", []string{"DB", "DB"}, []string{"r.p", "r.p"}},
		{"diamond twice", "on: push\njobs:\n  a:\n    runs-on: x\n    outputs:\n      x: ${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" +
			"  b:\n    needs: a\n    runs-on: x\n    outputs:\n      z: ${{ needs.a.outputs.x }}\n    steps:\n      - run: echo\n" +
			"  c:\n    needs: [a, b]\n    runs-on: x\n    steps:\n      - run: echo '${{ needs.b.outputs.z }}' '${{ needs.a.outputs.x }}'\n", []string{"DB", "DB"}, []string{"b.z", "a.x", "a.x"}},
		{"needs upper", "on: push\njobs:\n" + fmt.Sprintf(read, "${{ fromJSON(secrets.DB).pass }}") + "  print:\n    needs: [R]\n    runs-on: x\n    steps:\n      - run: echo '${{ needs.r.outputs.p }}'\n", []string{"DB"}, []string{"r.p"}},
		{"container env", "on: push\njobs:\n" + fmt.Sprintf(read, "${{ fromJSON(secrets.DB).pass }}") + "  print:\n    needs: r\n    runs-on: x\n    container:\n      image: i\n      env:\n        P: ${{ needs.r.outputs.p }}\n    steps:\n      - run: echo\n", []string{"DB"}, []string{"r.p"}},
		{"star", wf("${{ fromJSON(secrets.DB).pass }}", "${{ needs.*.outputs.p }}"), nil, nil},
		{"star toJSON", wf("${{ fromJSON(secrets.DB).pass }}", "${{ toJSON(needs.*.outputs.p) }}"), []string{"DB"}, []string{"r.p"}},
		{"token", wf("${{ github.token }}-${{ fromJSON(secrets.DB).pass }}", "${{ needs.r.outputs.p }}"), nil, nil},
		// the whole env with a whole secret: the runner drops the output
		{"toJSON(env)", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      T: ${{ secrets.T }}\n      P: ${{ fromJSON(secrets.DB).pass }}\n    outputs:\n      p: ${{ toJSON(env) }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"DB"}, nil},
		// the whole env written in a string is Object: the output keeps
		// the value taken out of a secret
		{"format(env)", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      T: ${{ secrets.T }}\n      P: ${{ fromJSON(secrets.DB).pass }}\n    outputs:\n      p: ${{ format('{0}', env) }}-${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"DB", "DB"}, []string{"r.p"}},
		{"env in a string", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      T: ${{ secrets.T }}\n    outputs:\n      p: ${{ env }}-${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"T,DB"}, []string{"r.p"}}, // the names are of every secret the value is read from
		// toJSON(secrets) in a variable of the env: the runner masks the
		// values of the JSON of the whole env
		{"toJSON(env) with the context", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      S: ${{ toJSON(secrets) }}\n      P: ${{ fromJSON(secrets.DB).pass }}\n    outputs:\n      p: ${{ toJSON(env) }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"DB"}, nil},
		// || gives one operand: an object is truthy, so the JSON of the
		// object, without the whole secret
		// a variable that the index or a property not named picks in some
		// runs only
		{"env index", "on: push\njobs:\n  r:\n    runs-on: x\n    strategy:\n      matrix:\n        k: [N]\n    env:\n      T: ${{ secrets.T }}\n      N: plain\n    outputs:\n      p: ${{ env[matrix.k] }}-${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"T,DB"}, []string{"r.p"}},
		{"env property", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      T: ${{ secrets.T }}\n      N: plain\n    outputs:\n      p: ${{ (github.event_name != '' && env).N }}-${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"T,DB"}, []string{"r.p"}},
		{"env star not named", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      T: ${{ secrets.T }}\n      P: ${{ fromJSON(secrets.DB).pass }}\n    outputs:\n      p: ${{ toJSON((github.event_name != '' && env).*) }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"DB"}, nil},
		{"or env", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      T: ${{ secrets.T }}\n    outputs:\n      p: ${{ toJSON(fromJSON(secrets.DB) || env) }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"DB,T"}, []string{"r.p"}},
		// a nearer env that may hide the variable: an env written as one
		// ${{ }}, a name in another case where the OS is not decided
		{"dynamic env", "on: push\nenv:\n  T: ${{ secrets.T }}\njobs:\n  r:\n    runs-on: x\n    env: ${{ fromJSON(vars.E) }}\n    outputs:\n      p: ${{ env.T }}-${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"T,DB"}, []string{"r.p"}},
		{"case not decided", "on: push\nenv:\n  T: ${{ secrets.T }}\njobs:\n  r:\n    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [windows-latest]\n    env:\n      t: plain\n    outputs:\n      p: ${{ env.T }}-${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"T,DB"}, []string{"r.p"}},
		{"case on Linux", "on: push\nenv:\n  T: ${{ secrets.T }}\njobs:\n  r:\n    runs-on: ubuntu-latest\n    env:\n      t: plain\n    outputs:\n      p: ${{ env.T }}-${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), nil, nil},
		{"toJSON of ||", wf("${{ toJSON(fromJSON(secrets.DB) || secrets.T) }}", "${{ needs.r.outputs.p }}"), []string{"DB,T"}, []string{"r.p"}},
		{"join(env.*)", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      T: ${{ secrets.T }}\n      P: ${{ fromJSON(secrets.DB).pass }}\n    outputs:\n      p: ${{ join(env.*, ',') }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"DB"}, nil},
		// the outputs see the env of the job and of the workflow
		{"masked env", "on: push\njobs:\n  r:\n    runs-on: x\n    env:\n      T: ${{ secrets.T }}\n    outputs:\n      p: ${{ env.T }}-${{ fromJSON(secrets.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), nil, nil},
		{"env part", "on: push\nenv:\n  DB: ${{ secrets.DB }}\njobs:\n  r:\n    runs-on: x\n    outputs:\n      p: ${{ fromJSON(env.DB).pass }}\n    steps:\n      - run: echo\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), []string{"DB"}, []string{"r.p"}},
		{"result", wf("${{ fromJSON(secrets.DB).pass }}", "${{ needs.r.result }}"), nil, nil},
		{"called", "on: push\njobs:\n  r:\n    uses: ./.github/workflows/c.yml\n" + fmt.Sprintf(print, "${{ needs.r.outputs.p }}"), nil, nil}, // called-output
		{"cycle", "on: push\njobs:\n  a:\n    needs: b\n    runs-on: x\n    outputs:\n      o: ${{ needs.b.outputs.o }}\n    steps:\n      - run: echo '${{ needs.b.outputs.o }}'\n" +
			"  b:\n    needs: a\n    runs-on: x\n    outputs:\n      o: ${{ needs.a.outputs.o }}\n    steps:\n      - run: echo\n", nil, nil},
	} {
		var parts, via []string
		for _, p := range SecretParts(parse(t, c.src)) {
			parts = append(parts, strings.Join(p.Secrets, ","))
			for _, v := range p.Via {
				via = append(via, v.Job+"."+v.Output)
			}
		}
		if !slices.Equal(parts, c.parts) || !slices.Equal(via, c.via) {
			t.Errorf("%s: got %q via %q, want %q via %q", c.name, parts, via, c.parts, c.via)
		}
	}
}

// TestCalledOnly: workflow_call alone, and with another event.
func TestCalledOnly(t *testing.T) {
	if !CalledOnly(parse(t, "on: workflow_call\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n")) {
		t.Error("workflow_call alone")
	}
	if CalledOnly(parse(t, "on: [workflow_call, push]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n")) {
		t.Error("with push")
	}
}
