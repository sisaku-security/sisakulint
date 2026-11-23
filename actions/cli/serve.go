package cli

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/reportview"
	"github.com/gh-intel/sisakulint/actions/rules"
)

// serveFlag is --serve, alone (on reportview.DefaultServeAddr) or with
// =ADDR, a loopback address and port.
type serveFlag struct {
	set  bool
	addr netip.AddrPort
}

func (s *serveFlag) String() string {
	if !s.set {
		return ""
	}
	return s.addr.String()
}

func (s *serveFlag) IsBoolFlag() bool { return true }

func (s *serveFlag) Set(v string) error {
	if v == "true" {
		s.set, s.addr = true, reportview.DefaultServeAddr
		return nil
	}
	a, err := reportview.ParseServeAddr(v)
	if err != nil {
		return err
	}
	s.set, s.addr = true, a
	return nil
}

// registryFlag is --registry, alone or =full.
type registryFlag struct{ set, full bool }

func (r *registryFlag) String() string {
	if r.full {
		return "full"
	}
	return ""
}

func (r *registryFlag) IsBoolFlag() bool { return true }

func (r *registryFlag) Set(v string) error {
	switch v {
	case "true":
		r.set = true
	case "full":
		r.set, r.full = true, true
	default:
		return fmt.Errorf("%q is not a registry (full, or none)", v)
	}
	return nil
}

// examplesFlag is --examples, alone (every rule) or =RULE.
type examplesFlag struct {
	set  bool
	rule lint.RuleID // zero: every rule
}

func (x *examplesFlag) String() string {
	if x.rule.IsZero() {
		return ""
	}
	return x.rule.String()
}

func (x *examplesFlag) IsBoolFlag() bool { return true }

func (x *examplesFlag) Set(v string) error {
	if v == "true" {
		x.set = true
		return nil
	}
	id, err := lint.ParseRuleID(v)
	if err != nil {
		return err
	}
	x.set, x.rule = true, id
	return nil
}

// examples runs the examples of the rules and the quality rules
// (--examples) and writes the catalog (--html) or serves it (--serve).
func examples(ctx context.Context, e Env, reg *lint.Registry, o options) int {
	fail := func(code int, err error) int {
		fmt.Fprintf(e.Stderr, "sisakulint: %v\n", err)
		return code
	}
	var only []lint.RuleID
	if !o.examples.rule.IsZero() {
		if _, ok := reg.Meta(o.examples.rule); !ok && !reg.IsQuality(o.examples.rule) {
			return fail(ExitUsage, fmt.Errorf("--examples: %s is neither a rule nor a quality rule", o.examples.rule))
		}
		only = append(only, o.examples.rule)
	}
	checks, err := rules.CheckAllExamples(ctx)
	if err != nil {
		return fail(ExitIO, err)
	}
	review, err := rules.Review(checks)
	if err != nil {
		return fail(ExitIO, err)
	}
	c, err := reportview.BuildCatalog(ctx, reg, checks.Of(only...), rules.AttackMarkers, review)
	if err != nil {
		return fail(ExitIO, err)
	}
	page, err := c.HTML()
	if err != nil {
		return fail(ExitIO, err)
	}
	if o.htmlOut != "" {
		if err := writeFileAtomic(o.htmlOut, page); err != nil {
			return fail(ExitIO, fmt.Errorf("--html: %w", err))
		}
	}
	if o.serve.set {
		err := reportview.Serve(ctx, o.serve.addr, page, func(url string) {
			fmt.Fprintf(e.Stderr, "sisakulint: serving the examples at %s (interrupt to stop)\n", url)
		})
		if err != nil {
			return fail(ExitIO, fmt.Errorf("--serve: %w", err))
		}
	}
	return 0
}
