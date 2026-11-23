package workflow

import (
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
)

// ImageReference is a Docker image as written: name[:tag][@digest]. A :
// after the last / starts the tag; one before it is a registry's port.
// The spans of the pieces are in the value of the String it is read from.
type ImageReference struct {
	Name, Tag, Digest Piece
}

// digestLengths are the algorithms of a digest docker pulls by, and the
// length of their lower-case hexadecimal; docker refuses
// a digest of any other form.
var digestLengths = map[string]int{"sha256": 64, "sha384": 96, "sha512": 128}

// Pinned is whether a digest pins the image. An image with a tag and a
// digest is pulled by the digest.
func (r ImageReference) Pinned() bool {
	alg, hex, ok := strings.Cut(r.Digest.Text, ":")
	n, known := digestLengths[alg]
	if !ok || !known || len(hex) != n {
		return false
	}
	for i := 0; i < len(hex); i++ {
		if c := hex[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// imageReference reads v as an image; the spans are in v, moved by at. It
// is false when v has no name, or an empty tag or digest.
func imageReference(v string, at int) (ImageReference, bool) {
	var r ImageReference
	piece := func(start, end int) Piece {
		return Piece{Text: v[start:end], Span: expr.Span{Start: at + start, End: at + end}}
	}
	end := len(v)
	if i := strings.IndexByte(v, '@'); i >= 0 {
		if i+1 == len(v) {
			return ImageReference{}, false
		}
		r.Digest = piece(i+1, len(v))
		end = i
	}
	if c := strings.LastIndexByte(v[:end], ':'); c > strings.LastIndexByte(v[:end], '/') {
		if c+1 == end {
			return ImageReference{}, false
		}
		r.Tag = piece(c+1, end)
		end = c
	}
	if end == 0 {
		return ImageReference{}, false
	}
	r.Name = piece(0, end)
	return r, true
}

// ImageReferenceOf reads s, the image of a job's container or of a
// service, as an image; false when it has a ${{ }} or is not one.
func ImageReferenceOf(s String) (ImageReference, bool) {
	if s.Parts != nil {
		return ImageReference{}, false
	}
	return imageReference(s.Text(), 0)
}

// DockerImageOf reads s, the image of an action.yml's runs, as an image
// when it is docker://image, which the runner matches ignoring case; a
// path to a Dockerfile is false.
func DockerImageOf(s String) (ImageReference, bool) {
	const scheme = "docker://"
	t := s.Text()
	if s.Parts != nil || len(t) < len(scheme) || !strings.EqualFold(t[:len(scheme)], scheme) {
		return ImageReference{}, false
	}
	return imageReference(t[len(scheme):], len(scheme))
}
