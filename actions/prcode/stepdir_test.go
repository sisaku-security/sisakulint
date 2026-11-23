package prcode

import (
	"slices"
	"testing"
)

// TestStepCwd: the directory the shell of a run step starts in, by the
// step's working-directory, else the job's, else the workflow's
// defaults.run.working-directory, key by key; a composite action's step
// by its own only.
func TestStepCwd(t *testing.T) {
	for _, c := range []struct {
		name, workflowDefaults, jobDefaults, step string
		base                                      wordBase
		path                                      string
		open                                      bool
	}{
		{"none", "", "", "", wordWorkspace, ".", false},
		{"the step's", "", "", "working-directory: web", wordWorkspace, "web", false},
		{"the job's", "", "working-directory: a", "", wordWorkspace, "a", false},
		{"the step's over the job's", "", "working-directory: a", "working-directory: web", wordWorkspace, "web", false},
		// a default setting of the job overrides the one of the same name
		// of the workflow, and only that one
		{"the workflow's under a job's shell", "working-directory: b", "shell: bash", "", wordWorkspace, "b", false},
		{"runner.temp", "", "", "working-directory: ${{ runner.temp }}/x", wordRunnerTemp, "x", false},
		{"an expression", "", "", "working-directory: ${{ inputs.dir }}", wordAnywhere, "", true},
		// the runner does not expand $RUNNER_TEMP in working-directory
		{"a parameter is letters", "", "", "working-directory: $RUNNER_TEMP", wordWorkspace, "$RUNNER_TEMP", false},
		// ../<repository>/x is in the workspace <work>/<repository>/<repository>
		{"out of the workspace by .. may come back", "", "", "working-directory: ../x", wordAnywhere, "", true},
		{"an absolute path may be the workspace", "", "", "working-directory: /opt/x", wordAnywhere, "", true},
	} {
		src := "on: push\n"
		if c.workflowDefaults != "" {
			src += "defaults:\n  run:\n    " + c.workflowDefaults + "\n"
		}
		src += "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
		if c.jobDefaults != "" {
			src += "    defaults:\n      run:\n        " + c.jobDefaults + "\n"
		}
		src += "    steps:\n      - run: npm ci\n"
		if c.step != "" {
			src += "        " + c.step + "\n"
		}
		w := mustWorkflow(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		got := stepCwd(w, &j, j.Steps.Value.Items[0])
		if got.base != c.base || got.open != c.open || !c.open && got.path != c.path {
			t.Errorf("%s: %+v; want base %v path %q open %v", c.name, got, c.base, c.path, c.open)
		}
	}
}

// TestStepCwdComposite: a composite action's step has no job: only its
// own working-directory counts.
func TestStepCwdComposite(t *testing.T) {
	a := mustAction(t, "name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - run: npm ci\n      shell: bash\n    - run: npm ci\n      shell: bash\n      working-directory: web\n")
	steps := a.Runs.Value.Steps.Value
	if got := stepCwd(nil, nil, steps.Items[0]); got.path != "." || got.base != wordWorkspace {
		t.Errorf("no working-directory: %+v", got)
	}
	if got := stepCwd(nil, nil, steps.Items[1]); got.path != "web" {
		t.Errorf("working-directory: %+v", got)
	}
}

// TestEvidenceWorkingDirectory: a tool reads the directory its step runs
// in; a step with cd, pushd or popd may run it anywhere.
func TestEvidenceWorkingDirectory(t *testing.T) {
	for _, c := range []struct {
		name, jobExtra, with, after string
		runs                        []string
	}{
		{"npm in runner.temp", "", "", "      - run: npm ci\n        working-directory: ${{ runner.temp }}\n", []string{"npm ci"}},
		{"pnpm in runner.temp", "", "", "      - run: pnpm store prune\n        working-directory: ${{ runner.temp }}\n", []string{"pnpm store prune"}},
		{"a script in runner.temp", "", "", "      - run: ./build.sh\n        working-directory: ${{ runner.temp }}\n", []string{"./build.sh"}},
		{"npm in the job's default by an absolute path", "    defaults:\n      run:\n        working-directory: /opt/x\n", "", "      - run: npm ci\n", []string{"npm ci"}},
		{"npm in the job's default out of the tree", "    defaults:\n      run:\n        working-directory: ../x\n", "", "      - run: npm ci\n", []string{"npm ci"}},
		// env's -C and sudo's -D among their own options; sudo's -C is
		// --close-from, and -C of the command they run is that command's
		{"sudo make -C is make's", "", ", path: pr", "      - run: sudo make -C build\n", nil},
		{"env make -C is make's", "", ", path: pr", "      - run: env CI=1 make -C build\n", nil},
		{"sudo -C closes descriptors", "", ", path: pr", "      - run: sudo -C 3 ./build.sh\n", nil},
		{"sudo -D the tree's directory", "", ", path: pr", "      - run: sudo -D pr make\n", []string{"sudo -D pr make"}},
		{"builtin cd back to the workspace", "", "", "      - run: builtin cd \"$GITHUB_WORKSPACE\" && npm ci\n        working-directory: ${{ runner.temp }}\n", []string{"npm ci"}},
		{"env -C the workspace", "", "", "      - run: env -C \"$GITHUB_WORKSPACE\" npm ci\n        working-directory: ${{ runner.temp }}\n", []string{"env -C \"$GITHUB_WORKSPACE\" npm ci"}},
		{"Set-Location after another statement", "", "", "      - run: $ErrorActionPreference = 'Stop'; Set-Location $env:GITHUB_WORKSPACE; npm ci\n        shell: pwsh\n        working-directory: ${{ runner.temp }}\n", []string{"$ErrorActionPreference = 'Stop'; Set-Location $env:GITHUB_WORKSPACE; npm ci"}},
		{"make -C the workspace", "", "", "      - run: make -C \"$GITHUB_WORKSPACE\"\n        working-directory: ${{ runner.temp }}\n", []string{"make -C \"$GITHUB_WORKSPACE\""}},
		{"go -C the workspace", "", "", "      - run: go -C \"$GITHUB_WORKSPACE\" test ./...\n        working-directory: ${{ runner.temp }}\n", []string{"go -C \"$GITHUB_WORKSPACE\" test ./..."}},
		{"cargo --manifest-path of the workspace", "", "", "      - run: cargo --manifest-path \"$GITHUB_WORKSPACE/Cargo.toml\" build\n        working-directory: ${{ runner.temp }}\n", []string{"cargo --manifest-path \"$GITHUB_WORKSPACE/Cargo.toml\" build"}},
		{"mvn -f of the workspace", "", "", "      - run: mvn -f \"$GITHUB_WORKSPACE\" verify\n        working-directory: ${{ runner.temp }}\n", []string{"mvn -f \"$GITHUB_WORKSPACE\" verify"}},
		{"gradle -p the workspace", "", "", "      - run: gradle -p \"$GITHUB_WORKSPACE\" build\n        working-directory: ${{ runner.temp }}\n", []string{"gradle -p \"$GITHUB_WORKSPACE\" build"}},
		{"a relative path past an expression", "", "", "      - run: bash ../${{ github.event.repository.name }}/build.sh\n", []string{"bash ../${{ github.event.repository.name }}/build.sh"}},
		{"npm in the tree's directory", "", ", path: web", "      - run: npm ci\n        working-directory: web\n", []string{"npm ci"}},
		{"pnpm --dir the tree's directory", "", ", path: web", "      - run: pnpm --dir web install\n", []string{"pnpm --dir web install"}},
		{"pnpm --dir .. from a directory of the tree", "", "", "      - run: pnpm --dir .. install\n        working-directory: web\n", []string{"pnpm --dir .. install"}},
		{"pnpm --dir .. from the tree's directory", "", ", path: web", "      - run: pnpm --dir .. install\n        working-directory: web\n", []string{"pnpm --dir .. install"}},
		{"npm in an expression", "", "", "      - run: npm ci\n        working-directory: ${{ inputs.dir }}\n", []string{"npm ci"}},
		{"a script of the tree's directory", "", ", path: web", "      - run: ./build.sh\n        working-directory: web\n", []string{"./build.sh"}},
		{"cd back to the workspace", "", "", "      - run: cd $GITHUB_WORKSPACE && npm ci\n        working-directory: ${{ runner.temp }}\n", []string{"npm ci"}},
		{"cd into the tree", "", ", path: web", "      - run: cd web && npm ci\n", []string{"npm ci"}},
		{"cd out of the tree (cd-out-of-tree)", "", ", path: pr", "      - run: cd /tmp && npm ci\n", []string{"npm ci"}},
		{"pushd", "", ", path: web", "      - run: pushd web && npm ci\n", []string{"npm ci"}},
		{"a # within a word of pwsh is no comment", "", ", path: pr", "      - run: |\n          Invoke-WebRequest https://example.com/a#b -OutFile x; Set-Location pr\n          npm ci\n        shell: pwsh\n", []string{"npm ci"}},
		{"cd in a comment of pwsh", "", ", path: pr", "      - run: |\n          # build then cd back\n          npm ci\n        shell: pwsh\n", nil},
		{"Set-Location of pwsh", "", ", path: web", "      - run: |\n          Set-Location web\n          npm ci\n        shell: pwsh\n", []string{"npm ci"}},
	} {
		with := "{ref: '${{ github.event.pull_request.head.sha }}'" + c.with + "}"
		s := oneSite(t, "pull_request_target", c.jobExtra, "actions/checkout@v4", with, c.after)
		var got []string
		for _, e := range s.CodeRunSteps {
			got = append(got, e.Text)
		}
		if !slices.Equal(got, c.runs) {
			t.Errorf("%s: %q; want %q", c.name, got, c.runs)
		}
	}
}
