package core

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/ast"
	"golang.org/x/oauth2"
)

// maxTagPages is the number of pages to fetch for repository tags.
// The tag list is used only for HEAD direct match (fast path) and latestTag
// collection for auto-fix; correctness is guaranteed by the default branch
// reachability check, so one page (100 tags) is sufficient.
const maxTagPages = 1

type ImpostorCommitRule struct {
	BaseRule
	client               *github.Client
	clientOnce           sync.Once
	commitCache          map[string]*commitVerificationResult
	commitCacheMu        sync.Mutex
	tagCache             map[string][]*github.RepositoryTag
	tagCacheMu           sync.Mutex
	latestTagCache       map[string]string
	latestTagCacheMu     sync.Mutex
	defaultBranchCache   map[string]string
	defaultBranchCacheMu sync.Mutex
}

type commitVerificationResult struct {
	isImpostor bool
	latestTag  string // for auto-fix suggestion
	err        error
}

func ImpostorCommitRuleFactory() *ImpostorCommitRule {
	return &ImpostorCommitRule{
		BaseRule: BaseRule{
			RuleName: "impostor-commit",
			RuleDesc: "Detects impostor commits that exist in the fork network but not in the repository's branches or tags",
		},
		commitCache:        make(map[string]*commitVerificationResult),
		tagCache:           make(map[string][]*github.RepositoryTag),
		latestTagCache:     make(map[string]string),
		defaultBranchCache: make(map[string]string),
	}
}

var fullShaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func isFullSha(ref string) bool {
	return fullShaPattern.MatchString(ref)
}

func parseImpostorActionRef(usesValue string) (owner, repo, ref string, skip bool) {
	if isLocalAction(usesValue) || isDockerAction(usesValue) || strings.HasPrefix(usesValue, ".\\") {
		return "", "", "", true
	}

	owner, repo, ref, ok := parseActionRef(usesValue)
	if !ok {
		return "", "", "", true
	}
	return owner, repo, ref, false
}

func (rule *ImpostorCommitRule) getGitHubClient() *github.Client {
	rule.clientOnce.Do(func() {
		// Check for GITHUB_TOKEN environment variable for authenticated requests
		// Authenticated requests have higher rate limits (5000/hour vs 60/hour)
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			ts := oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: token},
			)
			tc := oauth2.NewClient(context.Background(), ts)
			rule.client = github.NewClient(tc)
		} else {
			rule.client = github.NewClient(http.DefaultClient)
		}
	})
	return rule.client
}

func (rule *ImpostorCommitRule) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	usesValue := action.Uses.Value
	owner, repo, ref, skip := parseImpostorActionRef(usesValue)
	if skip || !isFullSha(ref) {
		return nil
	}

	result := rule.verifyCommit(owner, repo, ref)
	if result.err != nil {
		// API errors should not fail the lint - just log and skip
		rule.Debug("Error verifying commit %s/%s@%s: %v", owner, repo, ref, result.err)
		return nil //nolint:nilerr // Intentional: API errors are logged but don't fail linting
	}

	if result.isImpostor {
		rule.Errorf(action.Uses.Pos,
			"potential impostor commit detected: the commit '%s' is not found in any branch or tag of '%s/%s'. "+
				"This could be a supply chain attack where an attacker created a malicious commit in a fork. "+
				"Verify the commit exists in the official repository or use a known tag instead. "+
				"See: https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd",
			ref, owner, repo)

		if result.latestTag != "" {
			rule.AddAutoFixer(NewStepFixer(step, &impostorCommitFixer{
				rule:      rule,
				owner:     owner,
				repo:      repo,
				latestTag: result.latestTag,
			}))
		}
	}

	return nil
}

func (rule *ImpostorCommitRule) verifyCommit(owner, repo, sha string) *commitVerificationResult {
	cacheKey := fmt.Sprintf("%s/%s@%s", owner, repo, sha)

	// First check without lock (fast path)
	rule.commitCacheMu.Lock()
	if result, ok := rule.commitCache[cacheKey]; ok {
		rule.commitCacheMu.Unlock()
		return result
	}
	rule.commitCacheMu.Unlock()

	// Perform verification (potentially slow)
	result := rule.doVerifyCommit(owner, repo, sha)

	// Double-checked locking: check again before caching to avoid duplicate work
	rule.commitCacheMu.Lock()
	if existingResult, ok := rule.commitCache[cacheKey]; ok {
		// Another goroutine already cached the result
		rule.commitCacheMu.Unlock()
		return existingResult
	}
	rule.commitCache[cacheKey] = result
	rule.commitCacheMu.Unlock()

	return result
}

func (rule *ImpostorCommitRule) doVerifyCommit(owner, repo, sha string) *commitVerificationResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := rule.getGitHubClient()
	repoKey := fmt.Sprintf("%s/%s", owner, repo)

	// Fast path: check if sha matches any tag HEAD directly (no extra API calls).
	tags := rule.getTags(ctx, client, owner, repo)
	var latestTag string
	for _, tag := range tags {
		// Check if SHA matches the commit the tag points to
		if tag.GetCommit().GetSHA() == sha {
			return &commitVerificationResult{isImpostor: false}
		}
		if latestTag == "" {
			tagName := tag.GetName()
			if strings.HasPrefix(tagName, "v") {
				latestTag = tagName
			}
		}
	}
	if latestTag == "" && len(tags) > 0 {
		latestTag = tags[0].GetName()
	}

	rule.latestTagCacheMu.Lock()
	if latestTag != "" {
		rule.latestTagCache[repoKey] = latestTag
	}
	rule.latestTagCacheMu.Unlock()

	// Primary check: is the commit reachable from the default branch?
	// A legitimate pinned commit must be an ancestor of some branch in the
	// official repository. An impostor commit (from a fork) would not be
	// reachable from any branch even though GitHub makes it accessible via the
	// parent repo's commit API.
	defaultBranch := rule.getDefaultBranch(ctx, client, owner, repo)
	if rule.isReachableFromBranch(ctx, client, owner, repo, defaultBranch, sha) {
		return &commitVerificationResult{isImpostor: false, latestTag: latestTag}
	}

	return &commitVerificationResult{isImpostor: true, latestTag: latestTag}
}

// getDefaultBranch returns the default branch name for the given repository,
// fetching it from the GitHub API on first call and caching the result.
func (rule *ImpostorCommitRule) getDefaultBranch(ctx context.Context, client *github.Client, owner, repo string) string {
	cacheKey := fmt.Sprintf("%s/%s", owner, repo)

	rule.defaultBranchCacheMu.Lock()
	if branch, ok := rule.defaultBranchCache[cacheKey]; ok {
		rule.defaultBranchCacheMu.Unlock()
		return branch
	}
	rule.defaultBranchCacheMu.Unlock()

	repoInfo, _, err := client.Repositories.Get(ctx, owner, repo)
	defaultBranch := "main" // fallback when API is unavailable
	if err == nil && repoInfo.GetDefaultBranch() != "" {
		defaultBranch = repoInfo.GetDefaultBranch()
	}

	rule.defaultBranchCacheMu.Lock()
	rule.defaultBranchCache[cacheKey] = defaultBranch
	rule.defaultBranchCacheMu.Unlock()

	return defaultBranch
}

// isReachableFromBranch reports whether sha is an ancestor of (or identical to)
// the HEAD of branchName. It uses the GitHub compare API: when base=branchHead
// and head=sha, a status of "behind" means sha is in branchHead's history.
func (rule *ImpostorCommitRule) isReachableFromBranch(ctx context.Context, client *github.Client, owner, repo, branch, sha string) bool {
	comparison, _, err := client.Repositories.CompareCommits(ctx, owner, repo, branch, sha, nil)
	if err != nil {
		return false
	}
	status := comparison.GetStatus()
	return status == "behind" || status == "identical"
}

func (rule *ImpostorCommitRule) getTags(ctx context.Context, client *github.Client, owner, repo string) []*github.RepositoryTag {
	cacheKey := fmt.Sprintf("%s/%s", owner, repo)

	rule.tagCacheMu.Lock()
	if tags, ok := rule.tagCache[cacheKey]; ok {
		rule.tagCacheMu.Unlock()
		return tags
	}
	rule.tagCacheMu.Unlock()

	var allTags []*github.RepositoryTag
	opts := &github.ListOptions{PerPage: 100}

	for range maxTagPages {
		tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, opts)
		if err != nil {
			break
		}
		allTags = append(allTags, tags...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	rule.tagCacheMu.Lock()
	rule.tagCache[cacheKey] = allTags
	rule.tagCacheMu.Unlock()

	return allTags
}


type impostorCommitFixer struct {
	rule      *ImpostorCommitRule
	owner     string
	repo      string
	latestTag string
}

func (f *impostorCommitFixer) RuleNames() string {
	return f.rule.RuleName
}

func (f *impostorCommitFixer) FixStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return fmt.Errorf("step is not an action")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := f.rule.getGitHubClient()
	sha, _, err := client.Repositories.GetCommitSHA1(ctx, f.owner, f.repo, f.latestTag, "")
	if err != nil {
		return fmt.Errorf("failed to get commit SHA for tag %s: %w", f.latestTag, err)
	}

	newUses := fmt.Sprintf("%s/%s@%s", f.owner, f.repo, sha)
	action.Uses.Value = newUses
	action.Uses.BaseNode.Value = newUses
	action.Uses.BaseNode.LineComment = f.latestTag

	return nil
}
