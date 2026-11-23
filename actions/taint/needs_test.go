package taint

import "testing"

// TestAnalyzeJobNeeds: the if of a job reads the results of the jobs it
// depends on directly, and a job whose if is true only when success() is
// true goes through the ifs of the jobs it needs (attacker.JobIfs).
func TestAnalyzeJobNeeds(t *testing.T) {
	const build = `on: issues
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo
`
	const run = `    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`
	// GitHub reads the if only when build succeeded
	check(t, build+"  test:\n    needs: build\n    if: needs.build.result == 'failure'\n"+run, false,
		"run github.event.issue.title NotControlled")
	check(t, build+"  test:\n    needs: build\n    if: contains(needs.*.result, 'failure')\n"+run, false,
		"run github.event.issue.title NotControlled")
	check(t, build+"  test:\n    needs: build\n    if: ${{ always() && needs.build.result == 'failure' }}\n"+run, false,
		"run github.event.issue.title Controlled issues")
	// a job is skipped when a job it needs is skipped
	skipped := `on: issues
jobs:
  build:
    if: false
    runs-on: ubuntu-latest
    steps:
      - run: echo
`
	check(t, skipped+"  test:\n    needs: build\n"+run, false,
		"run github.event.issue.title NotControlled")
	check(t, skipped+"  mid:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n  test:\n    needs: mid\n"+run, false,
		"run github.event.issue.title NotControlled")
	check(t, skipped+"  test:\n    needs: build\n    if: always()\n"+run, false,
		"run github.event.issue.title Controlled issues")
	check(t, skipped+"  mid:\n    needs: build\n    if: always()\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n  test:\n    needs: mid\n"+run, false,
		"run github.event.issue.title Controlled issues")
	// the if of a step reads the results of the jobs its job needs, when
	// the job runs only after they succeeded (attacker.StepIf)
	step := "    runs-on: ubuntu-latest\n    steps:\n      - if: needs.build.result == 'failure' || github.event.issue.title == 'x'\n        run: echo \"${{ github.event.issue.title }}\"\n"
	check(t, build+"  test:\n    needs: build\n"+step, false,
		"run github.event.issue.title NotControlled")
	check(t, build+"  test:\n    needs: build\n    if: always()\n"+step, false,
		"run github.event.issue.title Controlled issues")
}

// TestAnalyzeNeededNarrowing: the if of a job that the job needs narrows
// a reference as the if of the job itself does, while the job's if is
// true only when success() is true (jobNarrowingsOf).
func TestAnalyzeNeededNarrowing(t *testing.T) {
	const run = `    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.head_ref }}"
`
	pre := func(cond string) string {
		return "on: pull_request_target\njobs:\n  a:\n    if: " + cond + "\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
	}
	check(t, pre("github.head_ref == 'release'")+"  b:\n    needs: a\n"+run, false,
		"run github.head_ref NotControlled")
	check(t, pre("github.head_ref == 'release'")+"  mid:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n  b:\n    needs: mid\n"+run, false,
		"run github.head_ref NotControlled")
	check(t, pre("github.head_ref == 'release'")+"  b:\n    needs: a\n    if: always()\n"+run, false,
		"run github.head_ref Controlled pull_request_target")
	check(t, pre("github.head_ref != 'release'")+"  b:\n    needs: a\n"+run, false,
		"run github.head_ref Controlled pull_request_target")
}

// TestAnalyzeJobIfNarrowingReadsNeeds: the if of a job narrows a reference
// read with the results of the jobs it depends on directly: an if that
// calls no status function is read only when build succeeded, where
// needs.build.result == 'failure' is false.
func TestAnalyzeJobIfNarrowingReadsNeeds(t *testing.T) {
	const build = "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
	const run = "    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.head_ref }}\"\n"
	check(t, build+"  test:\n    needs: build\n    if: ${{ needs.build.result == 'failure' || github.head_ref == 'release' }}\n"+run, false,
		"run github.head_ref NotControlled")
	check(t, build+"  test:\n    needs: build\n    if: ${{ always() && (needs.build.result == 'failure' || github.head_ref == 'release') }}\n"+run, false,
		"run github.head_ref Controlled pull_request_target")
}
