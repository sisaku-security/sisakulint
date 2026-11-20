package cli

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/internal/corpus"
)

var findingsLine = regexp.MustCompile(`(?m)^(\d+) findings?`)

// On the real repositories, the text is written, its count is the
// report's, and the groups make it a third of the text with --verbose or
// less. Only with ACTIONS_CORPUS=full.
func TestTextCorpus(t *testing.T) {
	if !corpus.Full() {
		t.Skip("ACTIONS_CORPUS=full")
	}
	var dirs []string
	for _, group := range []string{"real-world", "sisakuintel", "labeler-token"} {
		ds, err := filepath.Glob(filepath.Join(corpus.Dir(t), "files", group, "*"))
		if err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, ds...)
	}
	for _, d := range dirs {
		rep, in := runText(t, d)
		var b bytes.Buffer
		if err := writeText(&b, rep, in, registry(t), textOptions{threshold: lint.SeverityInfo}); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		out := b.String()
		var long bytes.Buffer
		if err := writeText(&long, rep, in, registry(t), textOptions{detail: detailFull, threshold: lint.SeverityInfo}); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		var brief bytes.Buffer
		if err := writeText(&brief, rep, in, registry(t), textOptions{detail: detailSummary, threshold: lint.SeverityInfo}); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if s, n := strings.Count(brief.String(), "\n"), strings.Count(out, "\n"); s > n {
			t.Errorf("%s: %d lines in summary, more than the %d of normal", d, s, n)
		}
		m := findingsLine.FindStringSubmatch(out)
		if m == nil || m[1] != strconv.Itoa(len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))) {
			t.Errorf("%s: the count %v, want %d", d, m, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
		}
		if n, all := strings.Count(out, "\n"), strings.Count(long.String(), "\n"); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) > 50 && 3*n > all {
			t.Errorf("%s: %d lines, more than a third of the %d with --verbose", d, n, all)
		}
		var lines bytes.Buffer
		if err := writeLines(&lines, rep, in, registry(t), false); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if got := strings.Count(lines.String(), "\n"); got != lineCount(rep) {
			t.Errorf("%s: %d lines, want %d", d, got, lineCount(rep))
		}
	}
}
