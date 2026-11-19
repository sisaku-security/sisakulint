package shell

import (
	"slices"
	"testing"
)

// A place in a heredoc's body has its delimiter, as the shell compares it;
// the others have none.
func TestPlacesDelim(t *testing.T) {
	for _, c := range []struct {
		src  string
		want []Place
	}{
		{"cat << 'END'\n@@\nEND\necho @@", []Place{{Quoting: QuotedHeredoc, Delim: Delim{"END"}}, {Quoting: Unquoted}}},
		{"cat <<-\"E\"'N'D\n\t@@\n\tEND", []Place{{Quoting: QuotedHeredoc, Delim: Delim{"END"}}}},
		{"cat << END\n@@\nEND", []Place{{Quoting: Heredoc, Delim: Delim{"END"}}}},
		{"cat << '{'\n@@\n{", []Place{{Quoting: QuotedHeredoc, Delim: Delim{"{"}}}},
		{"bash << 'END'\n@@\nEND", []Place{{Quoting: CommandString, Delim: Delim{"END"}}}},
		{"cat << 'END'\n@@", []Place{{Quoting: QuotingUnknown, Delim: Delim{}}}}, // not closed
	} {
		src, at := marked(c.src)
		if got := Places(src, at); !slices.Equal(got, c.want) {
			t.Errorf("%q: %v, want %v", c.src, got, c.want)
		}
	}
}

// A place right after a unit read at once (an operator of two bytes) is
// the same whether the places inside the unit are asked or not.
func TestPlacesAfterAUnit(t *testing.T) {
	src := "echo a >&2\n"
	one, r1 := places(src, []int{9})
	all, r := places(src, []int{7, 8, 9})
	if one[0] != all[2] || r1[0] != r[2] {
		t.Errorf("alone %v %v, with the places before %v %v", one[0], r1[0], all[2], r[2])
	}
}

// TestPlacesCondOperand: what a place inside [[ ]] is read as, where the
// quoting of a string put there matters: the pattern after ==, = and !=
// and the regular expression after =~, but no other operand, since [[ ]]
// neither splits nor globs (bash's manual, [[ expression ]]).
func TestPlacesCondOperand(t *testing.T) {
	for _, c := range []struct {
		src  string
		want []CondOperand
	}{
		{`[[ @@x == y ]]`, []CondOperand{CondOperandString}},
		{`[[ x == @@y ]]`, []CondOperand{CondOperandPattern}},
		{`[[ x = @@y || x != @@y ]]`, []CondOperand{CondOperandPattern, CondOperandPattern}},
		{`[[ x =~ ^(a|@@b c)$ ]]`, []CondOperand{CondOperandPattern}},
		{`[[ "@@" == y && x == "@@" ]]`, []CondOperand{CondOperandString, CondOperandPattern}},
		{`[[ -n @@x && x < @@y ]]`, []CondOperand{CondOperandString, CondOperandString}},
		{`[[ @@x -nt y ]]`, []CondOperand{CondOperandString}},
		{`[[ @@x ]]`, []CondOperand{CondOperandString}},
		{`[[ 1 -eq @@x ]]`, []CondOperand{CondOperandNone}}, // arithmetic: code
		{`[[ x @@ y ]]`, []CondOperand{CondOperandNone}},    // not read
		{`echo @@ == x`, []CondOperand{CondOperandNone}},
	} {
		src, at := marked(c.src)
		var got []CondOperand
		for _, p := range Places(src, at) {
			got = append(got, p.CondOperand)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.src, got, c.want)
		}
	}
}
