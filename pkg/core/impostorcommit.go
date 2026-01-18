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

// Pagination limits for GitHub API requests
const (
	// maxTagPages is the maximum number of pages to fetch for repository tags.
	// With 100 items per page, this allows fetching up to 500 tags.
	maxTagPages = 5
	// maxBranchPages is the maximum number of pages to fetch for repository branches.
	// With 100 items per page, this allows fetching up to 300 branches.
	maxBranchPages = 3
)

type ImpostorCommitRule struct {
	BaseRule
	client           *github.Client
	clientOnce       sync.Once
	commitCache      map[string]*commitVerificationResult
	commitCacheMu    sync.Mutex
	tagCache         map[string][]*github.RepositoryTag
	tagCacheMu       sync.Mutex
	branchCache      map[string][]*github.Branch
	branchCacheMu    sync.Mutex
	latestTagCache   map[string]string
	latestTagCacheMu sync.Mutex
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
		commitCache:    make(map[string]*commitVerificationResult),
		tagCache:       make(map[string][]*github.RepositoryTag),
		branchCache:    make(map[string][]*github.Branch),
		latestTagCache: make(map[string]string),
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

	tags := rule.getTags(ctx, client, owner, repo)
	var latestTag string
	for _, tag := range tags {
		if tag.GetCommit().GetSHA() == sha {
			return &commitVerificationResult{isImpostor: false}
		}
		if latestTag == "" && tag.GetName() != "" {
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

	branches := rule.getBranches(ctx, client, owner, repo)
	for _, branch := range branches {
		if branch.GetCommit().GetSHA() == sha {
			return &commitVerificationResult{isImpostor: false}
		}
	}

	branchCommitsURL := fmt.Sprintf("repos/%s/%s/commits/%s/branches-where-head", owner, repo, sha)
	req, err := client.NewRequest("GET", branchCommitsURL, nil)
	if err == nil {
		var branchList []*github.Branch
		resp, err := client.Do(ctx, req, &branchList)
		if err == nil && resp.StatusCode == http.StatusOK && len(branchList) > 0 {
			return &commitVerificationResult{isImpostor: false, latestTag: latestTag}
		}
	}

	mainBranches := []string{"main", "master", "develop"}
	for _, branchName := range mainBranches {
		comparison, _, err := client.Repositories.CompareCommits(ctx, owner, repo, branchName, sha, nil)
		if err != nil {
			continue
		}
		status := comparison.GetStatus()
		if status == "behind" || status == "identical" {
			return &commitVerificationResult{isImpostor: false, latestTag: latestTag}
		}
	}

	for _, tag := range tags {
		tagSha := tag.GetCommit().GetSHA()
		if tagSha == "" {
			continue
		}
		comparison, _, err := client.Repositories.CompareCommits(ctx, owner, repo, tagSha, sha, nil)
		if err != nil {
			continue
		}
		status := comparison.GetStatus()
		if status == "behind" || status == "identical" {
			return &commitVerificationResult{isImpostor: false, latestTag: latestTag}
		}
	}

	return &commitVerificationResult{isImpostor: true, latestTag: latestTag}
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

func (rule *ImpostorCommitRule) getBranches(ctx context.Context, client *github.Client, owner, repo string) []*github.Branch {
	cacheKey := fmt.Sprintf("%s/%s", owner, repo)

	rule.branchCacheMu.Lock()
	if branches, ok := rule.branchCache[cacheKey]; ok {
		rule.branchCacheMu.Unlock()
		return branches
	}
	rule.branchCacheMu.Unlock()

	var allBranches []*github.Branch
	opts := &github.BranchListOptions{ListOptions: github.ListOptions{PerPage: 100}}

	for range maxBranchPages {
		branches, resp, err := client.Repositories.ListBranches(ctx, owner, repo, opts)
		if err != nil {
			break
		}
		allBranches = append(allBranches, branches...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	rule.branchCacheMu.Lock()
	rule.branchCache[cacheKey] = allBranches
	rule.branchCacheMu.Unlock()

	return allBranches
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
