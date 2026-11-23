package prcode

import (
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

const (
	// ExprMark stands in a PathLine for a ${{ }} whose value is not known.
	ExprMark = "\x01"
	// RunnerTempMark stands in a PathLine for ${{ runner.temp }} at the head
	// of a line: a directory out of the workspace.
	RunnerTempMark = "\x00runner.temp"
)

// PathLine is a line of a value of paths, such as the path of
// actions/cache or actions/upload-artifact, one pattern a line.
type PathLine struct {
	// Text is the line with ${{ github.workspace }} at its head (after
	// spaces) as ., ${{ runner.temp }} at its head (after spaces and one !)
	// as RunnerTempMark, and each other ${{ }} as ExprMark. The ${{ }} are
	// read by their syntax: github['workspace'] is github.workspace.
	Text string
	// Raw is the line as written, with a line break inside a ${{ }} written
	// as a space, so that the line reads as one line in a note.
	Raw string
}

// PathLines are the lines of v. A value with no ${{ }} (or one GitHub
// folds to a string) is read as its string, with no mark. A ${{ }} that
// goes across a line break is in the line where it starts.
func PathLines(v workflow.String) []PathLine {
	if !v.HasExpr() {
		var out []PathLine
		for _, l := range strings.Split(v.AsString(), "\n") {
			out = append(out, PathLine{Text: l, Raw: l})
		}
		return out
	}
	text := v.Text()
	var out []PathLine
	var line strings.Builder
	start := 0 // where the line starts in text
	for _, p := range v.Parts {
		if !p.Expr {
			seg := text[p.Span.Start:p.Span.End]
			for {
				i := strings.IndexByte(seg, '\n')
				if i < 0 {
					line.WriteString(seg)
					break
				}
				line.WriteString(seg[:i])
				end := p.Span.End - len(seg) + i
				out = append(out, PathLine{Text: line.String(), Raw: oneLine(text[start:end])})
				line.Reset()
				start = end + 1
				seg = seg[i+1:]
			}
			continue
		}
		head := line.String()
		switch {
		case p.Tree != nil && strings.TrimSpace(head) == "" && expr.IsPath(p.Tree, "github", "workspace"):
			line.Reset()
			line.WriteString(".")
		case p.Tree != nil && tempHead(head) && expr.IsPath(p.Tree, "runner", "temp"):
			line.WriteString(RunnerTempMark)
		default:
			line.WriteString(ExprMark)
		}
	}
	return append(out, PathLine{Text: line.String(), Raw: oneLine(text[start:])})
}

// oneLine is s with each line break made a space.
func oneLine(s string) string { return strings.ReplaceAll(s, "\n", " ") }

// tempHead is whether head, what a line has before a ${{ }}, is spaces
// with at most one ! among them.
func tempHead(head string) bool {
	t := strings.TrimSpace(head)
	return t == "" || t == "!"
}
