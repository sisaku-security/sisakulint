package main

import (
	"fmt"
	"strings"

	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/rules"
)

// title is the title of the review batch of rule that writes and removes
// n files.
func title(rule lint.RuleID, n int) string {
	files := "files"
	if n == 1 {
		files = "file"
	}
	return fmt.Sprintf("[bot] review batch: %s (%d %s)", rule, n, files)
}

// body is the description of the review batch of rule that writes write
// and removes remove, of the total files the rule's review needs: what it
// is, how to read it, and what to do when a file looks right and when one
// does not. What a person reads is the diff, not the description.
func body(rule lint.RuleID, write []rules.ReviewDocument, remove []rules.ReviewPath, total int) string {
	var s strings.Builder
	n := len(write) + len(remove)
	fmt.Fprintf(&s, "`go run ./actions/internal/reviewpr` が開いた review batch です（%s の %d file）。", rule, n)
	if n < total {
		fmt.Fprintf(&s, "この rule のレビューが要る %d file のうち %d file で、残りはこの PR の後の review batch に出ます。", total, n)
	}
	s.WriteString("\n\n")
	s.WriteString("**読み方**: 「Files changed」で読んでください。`meta.md` は rule の説明（`Example` を除いた `Meta`）で、ほかは `Example` 1 件ずつです。file ごとの「Viewed」で、読んだ所を残せます。`Example` を走らせた結果は `go run ./cmd/sisakulint --examples=" + rule.String() + " --serve` で見られます。\n\n")
	s.WriteString("**問題が無ければ**: merge してください。squash を勧めます（main の commit に PR 番号が残ります）。merge した file が「レビュー済み」になります。\n\n")
	s.WriteString("**気になる file があれば**: その file に comment を付けてください。その file を外すか、main で直します。新しい file なら、PR の branch でその file を開いて「…」の Delete file で消してから、残りを merge しても構いません（消した file は次の review batch にまた出ます）。直したい点は、この PR の file でなく main で直します（この PR の file は生成したものです）。\n\n")
	s.WriteString("書く file（`" + approvedRoot + rule.String() + "/` の下）:\n\n")
	for _, d := range write {
		s.WriteString("- `" + d.Path.String() + "`\n")
	}
	if len(remove) > 0 {
		s.WriteString("\n消す file（今の `Example` に当たらない approved document）:\n\n")
		for _, p := range remove {
			s.WriteString("- `" + p.String() + "`\n")
		}
	}
	return s.String()
}
