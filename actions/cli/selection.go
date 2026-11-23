package cli

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// selectFlag is the rules of --rule or --skip-rule (the keys rule and
// skip-rule): each value names a rule, or rules with IDs joined by commas.
type selectFlag struct {
	of  []lint.Selector
	set bool
}

func (f *selectFlag) String() string { return "" }

func (f *selectFlag) Set(s string) error {
	f.set = true
	for _, item := range strings.Split(s, ",") {
		if item == "" {
			return fmt.Errorf("an empty ID in %q", s)
		}
		sel, err := lint.ParseSelector(item)
		if err != nil {
			return err
		}
		f.of = append(f.of, sel)
	}
	return nil
}
