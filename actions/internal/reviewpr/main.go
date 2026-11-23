// Command reviewpr opens review batches: PRs that write a rule's approved
// documents (actions/rules/approved/<rule>/) as its review documents are
// now (rules.ReviewDocuments), one rule a PR, while fewer than --max-open
// are open, of the rules --rule names (all by default). A PR writes the rule's meta.md when it changed, the documents
// of its examples that changed (at most --batch of them, all by default),
// and removes the approved documents of no example now; merging it is a
// person's approval of what it writes. It
// closes the open review batches of a rule that is no more. It never
// merges, and never pushes with force.
//
// It writes the review documents built into it, so run it on a clean
// checkout of origin/main:
//
//	go run ./actions/internal/reviewpr [--rule ID,…] [--batch K] [--max-open N] [--dry-run]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/rules"
)

type options struct {
	batch, maxOpen int
	dryRun         bool
	rules          []lint.RuleID // the rules whose review batches may open; all when none
}

func main() {
	var o options
	flag.IntVar(&o.batch, "batch", 0, "the most documents of examples in a review batch; 0 for all of the rule's")
	flag.IntVar(&o.maxOpen, "max-open", 1, "the most review batches open at once")
	flag.BoolVar(&o.dryRun, "dry-run", false, "say what it would close and open, with the title and the body of each PR it would open, and write nothing")
	ruleSpec := flag.String("rule", "", "the rules whose review batches may open, separated by commas; all when empty")
	flag.Parse()
	if o.batch < 0 || o.maxOpen < 0 {
		fmt.Fprintln(os.Stderr, "reviewpr: --batch and --max-open are 0 or more")
		os.Exit(2)
	}
	checks, err := rules.CheckAllExamples(context.Background())
	var s rules.ReviewState
	if err == nil {
		s, err = rules.Review(checks)
	}
	if err == nil {
		o.rules, err = parseRules(*ruleSpec, s.Rules())
		if err != nil {
			fmt.Fprintln(os.Stderr, "reviewpr: --rule:", err)
			os.Exit(2)
		}
		err = runReview(execRunner{}, o, s.Rules(), s.Unknown(), os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "reviewpr:", err)
		os.Exit(1)
	}
}

// runReview closes the open review batches of rules not in rs (removed or
// renamed while the batch was open), tells the directories of approved
// documents of no rule (unknown), and opens review batches of the rules of
// rs that are not reviewed, as o says.
func runReview(r runner, o options, rs []rules.RuleReview, unknown []lint.RuleID, log io.Writer) error {
	if _, err := r.run("", "git", "fetch", "origin"); err != nil {
		return err
	}
	head, err := r.run("", "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	main, err := r.run("", "git", "rev-parse", "origin/main")
	if err != nil {
		return err
	}
	// the review documents are made of the code as well as the examples:
	// any change to a tracked file, and a new file of the code tree
	tracked, err := r.run("", "git", "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	untracked, err := r.run("", "git", "status", "--porcelain", "--", "actions", "cmd", "internal", "yaml", "go.mod", "go.sum")
	if err != nil {
		return err
	}
	dirty := strings.TrimSpace(tracked + untracked)
	var off error
	if strings.TrimSpace(head) != strings.TrimSpace(main) {
		off = fmt.Errorf("run it on origin/main (%s), not on %s: it writes the review documents built into it", strings.TrimSpace(main), strings.TrimSpace(head))
	} else if dirty != "" {
		off = fmt.Errorf("run it on origin/main: the checkout has changes not on it:\n%s", dirty)
	}
	if off != nil && !o.dryRun {
		return off
	}
	if off != nil {
		fmt.Fprintf(log, "(dry run of the review documents built in, which are not origin/main's: %v)\n", off)
	}
	for _, u := range unknown {
		fmt.Fprintf(log, "unknown %s: %s%s/ is no rule's; remove it\n", u, approvedRoot, u)
	}
	known := map[string]bool{} // the rules, whose review batches stay open
	for _, rv := range rs {
		known[rv.Rule.String()] = true
	}
	all, err := openReviews(r)
	if err != nil {
		return err
	}
	open := map[string]bool{} // the rules of the open review batches
	kept := 0
	for _, p := range all {
		rule, ok := ruleOfFiles(p)
		if !ok || known[rule] {
			if ok {
				open[rule] = true
			}
			kept++
			continue
		}
		if o.dryRun {
			fmt.Fprintf(log, "would close #%d: %s is no rule\n", p.Number, rule)
			continue
		}
		comment := rule + " は rule でなくなったので、この review batch を閉じます。"
		if _, err := r.run("", "gh", "pr", "close", fmt.Sprint(p.Number), "--delete-branch", "--comment", comment); err != nil {
			return err
		}
		fmt.Fprintf(log, "closed #%d: %s is no rule\n", p.Number, rule)
	}
	room := max(o.maxOpen-kept, 0)
	opened := 0
	for _, rv := range rs {
		if rv.Reviewed || open[rv.Rule.String()] || len(o.rules) > 0 && !slices.Contains(o.rules, rv.Rule) {
			continue
		}
		if opened == room {
			break
		}
		opened++
		write, remove := batchOf(rv, o.batch)
		branch, err := branchName(r, rv.Rule)
		if err != nil {
			return err
		}
		var paths []string
		for _, d := range write {
			paths = append(paths, d.Path.String())
		}
		what := strings.Join(paths, ", ")
		if len(remove) > 0 {
			var rm []string
			for _, p := range remove {
				rm = append(rm, p.String())
			}
			what += "; remove " + strings.Join(rm, ", ")
		}
		t := title(rv.Rule, len(write)+len(remove))
		total := len(rv.Changed) + len(rv.Stale)
		if o.dryRun {
			fmt.Fprintf(log, "would open %s: %s\n", branch, what)
			fmt.Fprintf(log, "\n----- title -----\n%s\n----- body -----\n%s----- end -----\n\n", t, body(rv.Rule, write, remove, total))
			continue
		}
		url, err := openBatch(r, branch, rv.Rule, write, remove, total)
		if err != nil {
			return err
		}
		fmt.Fprintf(log, "opened %s %s: %s\n", strings.TrimSpace(url), branch, what)
	}
	if opened == 0 {
		fmt.Fprintf(log, "nothing to open: %d review batches open, --max-open %d\n", kept, o.maxOpen)
	}
	return nil
}

// branchName is review/<rule>/<n>, n the least from 1 that origin has no
// branch of.
func branchName(r runner, rule lint.RuleID) (string, error) {
	for i := 1; ; i++ {
		name := fmt.Sprintf("review/%s/%d", rule, i)
		out, err := r.run("", "git", "ls-remote", "--heads", "origin", "refs/heads/"+name)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(out) == "" {
			return name, nil
		}
	}
}

// openBatch writes write and removes remove, the approved documents of
// rule, in a worktree of origin/main of its own, pushes it as branch and
// opens the PR; it gives the PR's URL.
func openBatch(r runner, branch string, rule lint.RuleID, write []rules.ReviewDocument, remove []rules.ReviewPath, total int) (string, error) {
	dir, err := os.MkdirTemp("", "reviewpr-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	wt := filepath.Join(dir, "wt")
	if _, err := r.run("", "git", "worktree", "add", "--detach", wt, "origin/main"); err != nil {
		return "", err
	}
	defer r.run("", "git", "worktree", "remove", "--force", wt)
	for _, d := range write {
		p := path.Join(approvedRoot+rule.String(), d.Path.String())
		full := filepath.Join(wt, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(full, []byte(d.Text), 0o644); err != nil {
			return "", err
		}
		if _, err := r.run(wt, "git", "add", "--", p); err != nil {
			return "", err
		}
	}
	for _, rel := range remove {
		if _, err := r.run(wt, "git", "rm", "-q", "--", path.Join(approvedRoot+rule.String(), rel.String())); err != nil {
			return "", err
		}
	}
	n := len(write) + len(remove)
	msg := fmt.Sprintf("docs: %s の approved document を書き換える（%d file）", rule, n)
	if _, err := r.run(wt, "git", "commit", "-m", msg); err != nil {
		return "", err
	}
	if _, err := r.run(wt, "git", "push", "origin", "HEAD:refs/heads/"+branch); err != nil {
		return "", err
	}
	url, err := r.run(wt, "gh", "pr", "create", "--base", "main", "--head", branch, "--title", title(rule, n), "--body", body(rule, write, remove, total))
	if err != nil {
		if _, derr := r.run("", "git", "push", "origin", "--delete", branch); derr != nil {
			return "", fmt.Errorf("%v; and the branch %s stays on origin: %v", err, branch, derr)
		}
		return "", err
	}
	return url, nil
}

// parseRules is spec, rule IDs separated by commas, as rules of rs: none
// when spec is empty. A name that is no rule of rs is an error.
func parseRules(spec string, rs []rules.RuleReview) ([]lint.RuleID, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	var out []lint.RuleID
	for _, name := range strings.Split(spec, ",") {
		id, err := lint.ParseRuleID(strings.TrimSpace(name))
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(rs, func(rv rules.RuleReview) bool { return rv.Rule == id }) {
			return nil, fmt.Errorf("%s is no rule with review documents", id)
		}
		out = append(out, id)
	}
	return out, nil
}
