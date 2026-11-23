package workflow

import "testing"

// TestImageReference: the name, the tag after the last
// : that is after the last /, and the digest after @; Pinned is a digest
// of go-digest's form.
func TestImageReference(t *testing.T) {
	const d64 = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const d96 = "sha384:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, c := range []struct {
		v                 string
		ok                bool
		name, tag, digest string
		pinned            bool
	}{
		{"alpine", true, "alpine", "", "", false},
		{"alpine:3", true, "alpine", "3", "", false},
		{"alpine:latest", true, "alpine", "latest", "", false},
		{"ghcr.io/o/app:1.2", true, "ghcr.io/o/app", "1.2", "", false},
		{"localhost:5000/app", true, "localhost:5000/app", "", "", false},
		{"registry.example.com:443/team/app:1.2", true, "registry.example.com:443/team/app", "1.2", "", false},
		{"alpine@" + d64, true, "alpine", "", d64, true},
		{"alpine:3@" + d64, true, "alpine", "3", d64, true},
		{"alpine@" + d96, true, "alpine", "", d96, true},
		{"alpine@sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef", true, "alpine", "", "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"alpine@foo", true, "alpine", "", "foo", false},
		{"alpine@sha256:0123", true, "alpine", "", "sha256:0123", false},
		{"alpine@md5:0123456789abcdef0123456789abcdef", true, "alpine", "", "md5:0123456789abcdef0123456789abcdef", false},
		{"alpine@x:", true, "alpine", "", "x:", false},
		{"alpine@:", true, "alpine", "", ":", false},
		{"alpine@", false, "", "", "", false},
		{"alpine:", false, "", "", "", false},
		{":3", false, "", "", "", false},
		{"", false, "", "", "", false},
	} {
		r, ok := imageReference(c.v, 0)
		if ok != c.ok || r.Name.Text != c.name || r.Tag.Text != c.tag || r.Digest.Text != c.digest || r.Pinned() != c.pinned {
			t.Errorf("%q: %+v %v, pinned %v", c.v, r, ok, r.Pinned())
			continue
		}
		if ok && c.v[r.Name.Span.Start:r.Name.Span.End] != c.name {
			t.Errorf("%q: the name's span %+v", c.v, r.Name.Span)
		}
	}
}

// TestDockerImageOf: runs.image is an image only after docker://, which
// the runner matches ignoring case; a path to a Dockerfile
// is not one. The spans are in the value.
func TestDockerImageOf(t *testing.T) {
	for _, c := range []struct {
		src  string
		ok   bool
		name string
	}{
		{"docker://alpine:3", true, "alpine"},
		{"DOCKER://alpine", true, "alpine"},
		{"Dockerfile", false, ""},
		{"docker/Dockerfile", false, ""},
		{"docker://", false, ""},
	} {
		a, _, _ := parseAction(t, "name: x\ndescription: x\nruns:\n  using: docker\n  image: "+c.src+"\n")
		r, ok := DockerImageOf(a.Runs.Value.Image.Value)
		if ok != c.ok || r.Name.Text != c.name {
			t.Errorf("%q: %+v %v", c.src, r, ok)
			continue
		}
		if ok && c.src[r.Name.Span.Start:r.Name.Span.End] != c.name {
			t.Errorf("%q: span %+v", c.src, r.Name.Span)
		}
	}
}
