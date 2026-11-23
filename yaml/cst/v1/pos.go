package cst

import (
	"sort"
	"unicode/utf8"
)

// Position is a 1-based line and a 1-based byte column.
type Position struct{ Line, Column int }

// buildLineStarts returns the offset of each line's first byte. Lines are
// separated by b-break ([28]): \r\n, \r or \n.
func buildLineStarts(src []byte) []uint32 {
	ls := []uint32{0}
	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '\r':
			if i+1 < len(src) && src[i+1] == '\n' {
				i++
			}
			ls = append(ls, uint32(i+1))
		case '\n':
			ls = append(ls, uint32(i+1))
		}
	}
	return ls
}

// line returns the 0-based line containing offset.
func (t *Tree) line(offset int) int {
	return sort.Search(len(t.lineStarts), func(i int) bool { return int(t.lineStarts[i]) > offset }) - 1
}

func (t *Tree) Position(offset int) Position {
	l := t.line(offset)
	return Position{l + 1, offset - int(t.lineStarts[l]) + 1}
}

// RuneColumn is the 1-based column counted in runes; an invalid UTF-8 byte
// counts as one rune.
func (t *Tree) RuneColumn(offset int) int {
	l := t.line(offset)
	return utf8.RuneCount(t.src[t.lineStarts[l]:offset]) + 1
}

// LineStart returns the offset of the first byte of the 1-based line, or
// len(src) past the last line.
func (t *Tree) LineStart(line int) int {
	if line < 1 || line > len(t.lineStarts) {
		return len(t.src)
	}
	return int(t.lineStarts[line-1])
}
