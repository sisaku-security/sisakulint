package rules

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestUnpinnedImages: the findings of unpinned-images on the images of a
// job, its services and its steps.
func TestUnpinnedImages(t *testing.T) {
	for _, c := range []struct {
		name, job string
		want      []lint.FindingArgs
		inc       int
	}{
		{"no tag", "    container: node\n", []lint.FindingArgs{UnpinnedImagesMutable{Image: "node", Site: analysis.ImageSiteKindContainer}}, 0},
		{"latest", "    container: {image: 'node:latest'}\n", []lint.FindingArgs{UnpinnedImagesMutable{Image: "node:latest", Tag: "latest", Site: analysis.ImageSiteKindContainer}}, 0},
		{"tag", "    container: node:18.20.4\n", []lint.FindingArgs{UnpinnedImagesMutable{Image: "node:18.20.4", Tag: "18.20.4", Site: analysis.ImageSiteKindContainer}}, 0},
		{"digest", "    container: node@" + digest + "\n", nil, 0},
		{"tag and digest", "    container: node:18@" + digest + "\n", nil, 0},
		{"refused digest", "    container: node@sha256:0123\n", nil, 0},
		{"service string", "    services:\n      redis: redis:7\n", []lint.FindingArgs{UnpinnedImagesService{Image: "redis:7", Tag: "7", Service: "redis"}}, 0},
		{"service mapping", "    services:\n      db: {image: postgres}\n", []lint.FindingArgs{UnpinnedImagesService{Image: "postgres", Service: "db"}}, 0},
		{"matrix", "    container: ${{ matrix.image }}\n    strategy:\n      matrix: {image: ['node:18', 'node@" + digest + "']}\n",
			[]lint.FindingArgs{UnpinnedImagesMutable{Image: "node:18", Tag: "18", Site: analysis.ImageSiteKindContainer}}, 0},
		{"input", "    container: ${{ inputs.image }}\n", nil, 1},
		// the container and two services that name the same value of the
		// matrix: a finding each (the anchor of a service)
		{"shared matrix value", "    container: ${{ matrix.img }}\n    services:\n      s1:\n        image: ${{ matrix.img }}\n      s2:\n        image: ${{ matrix.img }}\n    strategy:\n      matrix: {img: ['busybox:1.36']}\n",
			[]lint.FindingArgs{UnpinnedImagesService{Image: "busybox:1.36", Tag: "1.36", Service: "s1"}, UnpinnedImagesMutable{Image: "busybox:1.36", Tag: "1.36", Site: analysis.ImageSiteKindContainer}, UnpinnedImagesService{Image: "busybox:1.36", Tag: "1.36", Service: "s2"}}, 0},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + c.job + "    steps:\n      - run: echo\n"
		rep, _, _ := checkRules(t, []lint.Rule{UnpinnedImages}, wfFile(src), nil)
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != len(c.want) || len(rep.FindingsWith(lint.CertaintyInconclusive)) != c.inc {
			t.Errorf("%s: %+v %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
			continue
		}
		for i, w := range c.want {
			if rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i].Args != w || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i].Condition != nil {
				t.Errorf("%s: %+v, want %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i].Args, w)
			}
		}
	}
}

// TestUnpinnedImagesDocker: a step's docker:// in a workflow and in a
// composite action, and an action.yml's runs.image.
func TestUnpinnedImagesDocker(t *testing.T) {
	files := map[string]string{
		".github/workflows/w.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://alpine:3\n      - uses: docker://alpine@" + digest + "\n",
		"a/action.yml":            "name: x\ndescription: x\nruns:\n  using: docker\n  image: docker://alpine\n",
		"b/action.yml":            "name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine:3\n",
	}
	rep, in, _ := checkRules(t, []lint.Rule{UnpinnedImages}, files, nil)
	want := []string{".github/workflows/w.yml docker://alpine:3", "a/action.yml docker://alpine", "b/action.yml docker://alpine:3"}
	if got := at(t, rep, in); !slices.Equal(got, want) {
		t.Errorf("%v, want %v", got, want)
	}
}

// TestUnpinnedImagesNone: no finding on a job without an image, a workflow
// without jobs, and an action built from its Dockerfile.
func TestUnpinnedImagesNone(t *testing.T) {
	files := map[string]string{
		".github/workflows/w.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
		".github/workflows/v.yml": "on: push\n",
		"action.yml":              "name: x\ndescription: x\nruns:\n  using: docker\n  image: Dockerfile\n",
	}
	rep, _, _ := checkRules(t, []lint.Rule{UnpinnedImages}, files, nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
		t.Errorf("%+v %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// TestUnpinnedImagesIncidents: the workflows of the incident the Meta
// cites, which pulled aquasec/trivy with no tag while its latest was
// re-pointed:
// aquasecurity/trivy-ci-test 055a8a26f105bd366b27d72ed5a27556754c4279
// .github/workflows/scan.yml:13-16 and owncast/owncast
// 2dc92798604888e628a623ef82324b09eb35ca14
// .github/workflows/container-lint.yml:17-20.
func TestUnpinnedImagesIncidents(t *testing.T) {
	for _, src := range []string{
		"on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n    - name: Scan\n      uses: docker://aquasec/trivy\n      with:\n        args: --severity CRITICAL --no-progress trivy-ci-test:1.2.3\n",
		"on: push\njobs:\n  dockerfile:\n    name: Dockerfile\n    runs-on: ubuntu-latest\n    container:\n      image: aquasec/trivy\n    steps:\n      - run: echo\n",
	} {
		rep, _, _ := checkRules(t, []lint.Rule{UnpinnedImages}, wfFile(src), nil)
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != "unpinned-images.mutable" {
			t.Errorf("%q: %+v", src, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
	}
}
