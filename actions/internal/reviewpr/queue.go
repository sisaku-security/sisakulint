package main

import (
	"encoding/json"
	"strings"

	"github.com/gh-intel/sisakulint/actions/rules"
)

// approvedRoot is where the approved documents are, from the repository's
// root: approvedRoot<rule>/meta.md and approvedRoot<rule>/<what>/<id>.md.
const approvedRoot = "actions/rules/approved/"

// batchOf is what a review batch of rv writes and removes: meta.md when it
// changed, and the changed documents of examples, at most size of them
// when size is not 0, in the order of rv.Changed; and every stale approved
// document, which size does not count. Paths are under the rule's
// directory.
func batchOf(rv rules.RuleReview, size int) (write []rules.ReviewDocument, remove []rules.ReviewPath) {
	n := 0
	for _, d := range rv.Changed {
		if d.Example == nil {
			write = append(write, d)
			continue
		}
		if size == 0 || n < size {
			write = append(write, d)
			n++
		}
	}
	return write, rv.Stale
}

// openReview is an open review PR: its number, its branch and the files it
// changes.
type openReview struct {
	Number      int    `json:"number"`
	HeadRefName string `json:"headRefName"`
	Files       []struct {
		Path string `json:"path"`
	} `json:"files"`
}

// openReviews are the open PRs whose branches start with review/.
func openReviews(r runner) ([]openReview, error) {
	out, err := r.run("", "gh", "pr", "list", "--state", "open", "--limit", "1000", "--json", "number,headRefName,files")
	if err != nil {
		return nil, err
	}
	var all []openReview
	if err := json.Unmarshal([]byte(out), &all); err != nil {
		return nil, err
	}
	var reviews []openReview
	for _, p := range all {
		if strings.HasPrefix(p.HeadRefName, "review/") {
			reviews = append(reviews, p)
		}
	}
	return reviews, nil
}

// ruleOfFiles is the directory under approvedRoot of the first file p
// changes there: the rule p is a review batch of, which may be no rule now.
func ruleOfFiles(p openReview) (string, bool) {
	for _, f := range p.Files {
		if rest, ok := strings.CutPrefix(f.Path, approvedRoot); ok {
			if rule, _, ok := strings.Cut(rest, "/"); ok {
				return rule, true
			}
		}
	}
	return "", false
}
