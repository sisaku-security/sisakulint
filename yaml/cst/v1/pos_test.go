package cst

import "testing"

func treeOf(src string) *Tree {
	return &Tree{src: []byte(src), lineStarts: buildLineStarts([]byte(src))}
}

func TestPosition(t *testing.T) {
	cases := []struct {
		src     string
		off     int
		want    Position
		runeCol int
	}{
		{"", 0, Position{1, 1}, 1},
		{"a\nb", 2, Position{2, 1}, 1},
		{"a\r\nb", 3, Position{2, 1}, 1},
		{"a\r\nb", 2, Position{1, 3}, 3}, // between \r and \n: still the \r's line
		{"a\rb", 2, Position{2, 1}, 1},
		{"a\r\n\rb\n", 4, Position{3, 1}, 1},
		{"a\r\n\rb\n", 6, Position{4, 1}, 1}, // end of input after the last break
		{"ab", 2, Position{1, 3}, 3},
		{"# 日本語\nx", len("# 日本"), Position{1, 1 + len("# 日本")}, 5},
		{"v: 🙂x", len("v: 🙂"), Position{1, 1 + len("v: 🙂")}, 5},
		{"\xffa", 1, Position{1, 2}, 2},
	}
	for _, c := range cases {
		tr := treeOf(c.src)
		if got := tr.Position(c.off); got != c.want {
			t.Errorf("Position(%q, %d) = %v, want %v", c.src, c.off, got, c.want)
		}
		if got := tr.RuneColumn(c.off); got != c.runeCol {
			t.Errorf("RuneColumn(%q, %d) = %d, want %d", c.src, c.off, got, c.runeCol)
		}
	}
}

func TestLineStart(t *testing.T) {
	cases := []struct {
		src  string
		line int
		want int
	}{
		{"", 1, 0},
		{"a\nb", 2, 2},
		{"a\r\nb", 2, 3},
		{"a\rb", 2, 2},
		{"a\r\n\rb\n", 3, 4},
		{"a\r\n\rb\n", 4, 6},
	}
	for _, c := range cases {
		if got := treeOf(c.src).LineStart(c.line); got != c.want {
			t.Errorf("LineStart(%q, %d) = %d, want %d", c.src, c.line, got, c.want)
		}
	}
}
