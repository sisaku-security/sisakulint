package ir

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

const imageWF = `on: push
jobs:
  a:
    runs-on: x
    container:
      image: ghcr.io/o/build:1
      credentials: {username: u, password: hunter2}
    services:
      redis: redis
      db:
        image: postgres@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        credentials: {username: u, password: '${{ secrets.DB }}'}
    steps:
      - uses: docker://alpine:3
      - uses: actions/checkout@v4
      - uses: docker://alpine@sha256:0123
  b:
    runs-on: x
    container: ${{ matrix.image }}
    strategy:
      matrix:
        image: [node:18, 'node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', '${{ inputs.i }}']
    steps:
      - run: echo
  c:
    runs-on: x
    container:
      image: ${{ inputs.image }}
      credentials: {username: u, password: '${{ env.PW }}'}
    steps:
      - run: echo
`

// TestImageSiteProjection: every place, the matrix's
// values one by one, an image not read, and an image whose digest docker
// refuses, which is none.
func TestImageSiteProjection(t *testing.T) {
	x := newIR(t, imageWF)
	type img struct {
		text, tag      string
		pinned, matrix bool
	}
	type site struct {
		path    string
		kind    analysis.ImageSiteKind
		service string
		imgs    []img
		inc     int
	}
	want := []site{
		{"jobs.a.container", analysis.ImageSiteKindContainer, "", []img{{"ghcr.io/o/build:1", "1", false, false}}, 0},
		{"jobs.a.services.redis", analysis.ImageSiteKindService, "redis", []img{{"redis", "", false, false}}, 0},
		{"jobs.a.services.db", analysis.ImageSiteKindService, "db", []img{{"postgres@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "", true, false}}, 0},
		{"jobs.a.steps[0].uses", analysis.ImageSiteKindStep, "", []img{{"alpine:3", "3", false, false}}, 0},
		{"jobs.a.steps[2].uses", analysis.ImageSiteKindStep, "", nil, 0},
		{"jobs.b.container", analysis.ImageSiteKindContainer, "", []img{{"node:18", "18", false, true}, {"node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "", true, true}}, 1},
		{"jobs.c.container", analysis.ImageSiteKindContainer, "", nil, 1},
	}
	got := x.allImageSites()
	if len(got) != len(want) {
		t.Fatalf("%d sites: %+v", len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if g.key.Path() != w.path || g.site != w.kind || g.serviceName != w.service || len(g.images) != len(w.imgs) || len(g.inconclusiveImages) != w.inc {
			t.Errorf("%d: %s %v %q %+v %+v; want %+v", i, g.key.Path(), g.site, g.serviceName, g.images, g.inconclusiveImages, w)
			continue
		}
		for k, wi := range w.imgs {
			gi := g.images[k]
			if gi.Text != wi.text || gi.Tag != wi.tag || gi.Pinned != wi.pinned || gi.Matrix != wi.matrix {
				t.Errorf("%s %d: %+v, want %+v", w.path, k, gi, wi)
			}
		}
	}
}

// TestImageSiteAction: an action.yml's runs.image docker://, and the steps
// of a composite action; a Dockerfile is no image site.
func TestImageSiteAction(t *testing.T) {
	for _, c := range []struct {
		src  string
		want string
	}{
		{"name: x\ndescription: x\nruns:\n  using: docker\n  image: docker://alpine:3\n", "runs.image alpine:3"},
		{"name: x\ndescription: x\nruns:\n  using: docker\n  image: Dockerfile\n", ""},
		{"name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - uses: docker://alpine\n", "runs.steps[0].uses alpine"},
	} {
		tree, a := parseAction(t, c.src)
		x := New("action.yml", tree, nil, a)
		got := ""
		for _, s := range x.allImageSites() {
			got = s.key.Path() + " " + s.images[0].Text
		}
		if got != c.want {
			t.Errorf("%q: %q, want %q", c.src, got, c.want)
		}
	}
}

// TestRegistryCredentialsProjection: each container or service whose
// credentials have a password, by the form of the password.
func TestRegistryCredentialsProjection(t *testing.T) {
	x := newIR(t, imageWF)
	got := x.allRegistryCredentials()
	want := []struct {
		path, container string
		form            PasswordForm
	}{
		{"jobs.a.container", "container", PasswordFormLiteral},
		{"jobs.a.services.db", "services.db", PasswordFormSecret},
		{"jobs.c.container", "container", PasswordFormOther},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i, w := range want {
		if got[i].key.Path() != w.path || got[i].container != w.container || got[i].passwordForm != w.form {
			t.Errorf("%d: %s %s %v; want %+v", i, got[i].key.Path(), got[i].container, got[i].passwordForm, w)
		}
	}
}

// TestPasswordForm: the form of the password of a container's credentials:
// a literal (plain text), a secret, or another value, by what its ${{ }}
// gives.
func TestPasswordForm(t *testing.T) {
	for _, c := range []struct {
		password string
		want     PasswordForm
	}{
		{"hunter2", PasswordFormLiteral},
		{"'${PW}'", PasswordFormLiteral},
		{"${{ 'hunter2' }}", PasswordFormLiteral},
		{"${{ format('{0}', 'hunter2') }}", PasswordFormLiteral},
		{"${{ secrets.REG }}", PasswordFormSecret},
		{"${{ secrets['REG'] }}", PasswordFormSecret},
		{"${{ secrets.REG }}-suffix", PasswordFormSecret},
		{"${{ format('{0}', secrets.REG) }}", PasswordFormSecret},
		{"${{ env.PW }}", PasswordFormOther},
		{"${{ vars.PW }}", PasswordFormVariable},
		{"${{ vars['PW'] }}", PasswordFormVariable},
		{"${{ secrets.REG || vars.PW }}", PasswordFormVariable},
		{"${{ vars.PW }}${{ env.SUFFIX }}", PasswordFormOther},
		{"${{ format('{0}', vars.PW) }}", PasswordFormVariable},
		{"${{ inputs.pw }}", PasswordFormOther},
		{"${{ secrets.REG || 'hunter2' }}", PasswordFormLiteral},
		{"${{ secrets.REG && 'hunter2' || '' }}", PasswordFormLiteral},
		{"${{ github.token }}", PasswordFormSecret},
		{"${{ github.event.inputs.pw }}", PasswordFormOther},
		{"pre${{ secrets.REG }}", PasswordFormSecret},
	} {
		x := newIR(t, "on: push\njobs:\n  a:\n    runs-on: x\n    container:\n      image: a@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n      credentials:\n        username: u\n        password: "+c.password+"\n    steps:\n      - run: echo\n")
		got := x.allRegistryCredentials()
		if len(got) != 1 || got[0].passwordForm != c.want {
			t.Errorf("%s: %+v, want %v", c.password, got, c.want)
		}
	}
}

// TestImageSiteDynamic: services or credentials that are a whole ${{ }}
// are inconclusive, not dropped.
func TestImageSiteDynamic(t *testing.T) {
	x := newIR(t, "on: push\njobs:\n  a:\n    runs-on: x\n    services: ${{ fromJSON(inputs.s) }}\n    container:\n      image: a@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n      credentials: ${{ fromJSON(inputs.c) }}\n    steps:\n      - run: echo\n")
	sites := x.allImageSites()
	if len(sites) != 2 || len(sites[1].inconclusiveImages) != 1 || sites[1].site != analysis.ImageSiteKindService {
		t.Errorf("%+v", sites)
	}
	creds := x.allRegistryCredentials()
	if len(creds) != 2 || creds[0].passwordForm != PasswordFormOther || creds[1].passwordForm != PasswordFormOther {
		t.Errorf("%+v", creds)
	}
}

// TestRegistryCredentialsWholeExpr: a container or services that is a
// whole ${{ }} may hold credentials, so it is inconclusive; a container of
// the matrix whose values are all strings has none.
func TestRegistryCredentialsWholeExpr(t *testing.T) {
	for _, c := range []struct {
		job  string
		want int
	}{
		{"    container: ${{ matrix.c }}\n    strategy:\n      matrix:\n        c: [{image: 'x:1', credentials: {username: u, password: hunter2}}]\n", 1},
		{"    container: ${{ fromJSON(inputs.c) }}\n", 1},
		{"    services: ${{ fromJSON(inputs.s) }}\n", 1},
		{"    container: ${{ matrix.image }}\n    strategy:\n      matrix: {image: ['node:18', 'node:20']}\n", 0},
	} {
		x := newIR(t, "on: push\njobs:\n  a:\n    runs-on: x\n"+c.job+"    steps:\n      - run: echo\n")
		got := x.allRegistryCredentials()
		if len(got) != c.want || c.want == 1 && got[0].passwordForm != PasswordFormOther {
			t.Errorf("%q: %+v", c.job, got)
		}
	}
}

// TestInconclusiveDispatch: an image of a container, of a service, of the
// whole services or a value of the matrix, and a label of runs-on, whose
// ${{ }} has an input of workflow_dispatch are marked Dispatch; with
// workflow_call alone they are not.
func TestInconclusiveDispatch(t *testing.T) {
	const jobs = `jobs:
  a:
    runs-on: ${{ inputs.runner }}
    container: ${{ inputs.image }}
    services:
      db:
        image: ${{ inputs.image }}
    steps:
      - run: echo
  b:
    runs-on: x
    services: ${{ fromJSON(inputs.s) }}
    steps:
      - run: echo
  c:
    runs-on: x
    container: ${{ matrix.image }}
    strategy:
      matrix:
        image: ['${{ inputs.image }}']
    steps:
      - run: echo
`
	for _, c := range []struct {
		on   string
		want bool
	}{
		{"on:\n  workflow_dispatch:\n    inputs:\n      image: {}\n", true},
		{"on:\n  workflow_call:\n    inputs:\n      image: {type: string}\n", false},
	} {
		x := newIR(t, c.on+jobs)
		n := 0
		for _, s := range x.allImageSites() {
			for _, g := range s.inconclusiveImages {
				n++
				if g.Dispatch != c.want {
					t.Errorf("%s %s: Dispatch %v, want %v", c.on, g.Text, g.Dispatch, c.want)
				}
			}
		}
		if n != 4 {
			t.Errorf("%s: %d inconclusive images, want 4", c.on, n)
		}
		labels := x.allJobs()[0].inconclusiveLabels
		if len(labels) != 1 || labels[0].Dispatch != c.want {
			t.Errorf("%s: labels %+v, want Dispatch %v", c.on, labels, c.want)
		}
	}
}
