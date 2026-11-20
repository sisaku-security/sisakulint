package cli

import (
	"strings"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// directiveMarker is what a comment of a workflow has before the hosts
// that sisakulint 0.x allows in the workflow.
const directiveMarker = "sisakulint:secret-exfiltration.allowed-hosts:"

// legacyDirectives reads the directives of sisakulint 0.x in the workflow
// content. sisakulint 0.x reads a directive from the comments that its
// YAML library attaches to the top of the file; --init writes the hosts of
// a directive only at the places where sisakulint 0.x was seen to read the
// directive: a comment at the start of a line whose next line that is not
// blank and not a comment is a key of the top level, and a comment at the
// end of the line of a key of the top level, when the value of the key
// ends on that line or nothing but the colon is between the key and the
// comment (not "jobs: &j # ..." nor "on: [push, # ..."). taken are the hosts of those
// directives, comma by comma; left are the other directives, one for each
// comment, which --init does not write.
func legacyDirectives(content []byte) (taken, left []legacyItem) {
	t := cst.Parse(content)
	keyLines := map[int]bool{} // the lines of the keys of the top level
	valueEnds := map[int]int{} // by the line of a key of the top level, the line its value ends on
	for e := range t.Root().Children() {
		doc, ok := e.Node()
		if !ok || doc.Kind() != cst.NodeDocument {
			continue
		}
		if top, ok := documentContent(doc); ok {
			if m, ok := top.Mapping(); ok {
				for entry := range m.Entries() {
					if p := t.Position(entry.Key.Span().Start); p.Column == 1 {
						keyLines[p.Line] = true
						end := entry.Value.Span()
						valueEnds[p.Line] = t.Position(max(end.Start, end.End-1)).Line
					}
				}
			}
		}
		break // a workflow is one document
	}
	// line is the text of the line n (from 1) without its break, as the tree
	// counts the lines: YAML breaks a line at CR LF, LF and a CR alone.
	line := func(n int) string {
		return strings.TrimRight(string(content[t.LineStart(n):t.LineStart(n+1)]), "\r\n")
	}
	// nextIsKey is whether the first line after the line after (from 1) that is not
	// blank and not a comment is a line of a key of the top level.
	nextIsKey := func(after int) bool {
		for n := after + 1; t.LineStart(n) < len(content); n++ {
			s := strings.TrimSpace(line(n))
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			return keyLines[n]
		}
		return false
	}
	// lineEnd is whether the comment at p, on the line of a key of the top
	// level, is at the end of a value that ends on the line, or right after
	// the colon of the key.
	lineEnd := func(p cst.Position) bool {
		if !keyLines[p.Line] || p.Column == 1 {
			return false
		}
		before := strings.TrimSpace(line(p.Line)[:p.Column-1])
		return valueEnds[p.Line] == p.Line || strings.HasSuffix(before, ":")
	}
	for k := range t.Root().Tokens() {
		if k.Kind() != cst.TokComment {
			continue
		}
		text := string(k.Bytes())
		at := strings.Index(text, directiveMarker)
		if at < 0 {
			continue
		}
		p := t.Position(k.Span().Start)
		if !(p.Column == 1 && nextIsKey(p.Line) || lineEnd(p)) {
			left = append(left, legacyItem{strings.TrimSpace(text), p.Line})
			continue
		}
		for _, v := range strings.Split(text[at+len(directiveMarker):], ",") {
			if v = strings.TrimSpace(v); v != "" {
				taken = append(taken, legacyItem{v, p.Line})
			}
		}
	}
	return taken, left
}
