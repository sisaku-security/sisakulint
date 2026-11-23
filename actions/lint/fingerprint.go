package lint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/gh-intel/sisakulint/actions/facts"

	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
	"github.com/gh-intel/sisakulint/actions/ir"
)

// fingerprint is sha256 of the canonical JSON of {rule, input, path,
// anchor}, in hexadecimal. No line number goes in, so
// lines added elsewhere keep it.
func fingerprint(f FindingDraft, p *ir.Paths) (Fingerprint, error) {
	id, ok := identityOf(f, p)
	if !ok {
		return Fingerprint{}, errors.New("a location not made by At or AtSpan")
	}
	b, err := json.Marshal(map[string]string{"rule": f.Rule.s, "input": id.input.String(), "path": id.path, "anchor": id.anchor})
	if err != nil {
		return Fingerprint{}, err
	}
	c, err := jsonschema.Canonical(b)
	if err != nil {
		return Fingerprint{}, err
	}
	sum := sha256.Sum256(c)
	return Fingerprint{hex.EncodeToString(sum[:])}, nil
}

// identity is what a fingerprint is the hash of, less the rule. Two
// findings of one rule have one fingerprint exactly when they have one
// identity; comparing identities spares hashing each finding of each input
// a fix is checked on.
type identity struct {
	input        facts.InputPath
	path, anchor string
}

func identityOf(f FindingDraft, p *ir.Paths) (identity, bool) {
	if f.Location.tree == nil {
		return identity{}, false
	}
	return identity{f.Location.File.Input, p.Of(f.Location.tree, f.Location.node, f.Location.vias), f.Anchor}, true
}

// pathOf is the path of the element where l is (ir.Paths.Of).
func pathOf(l Location) string { return ir.NewPaths().Of(l.tree, l.node, l.vias) }
