package core

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/ast"
)

type CommitSha struct {
	BaseRule
	githubToken string
	clientOnce  sync.Once
	client      *github.Client
}

func CommitShaRule(token string) *CommitSha {
	return &CommitSha{
		BaseRule: BaseRule{
			RuleName: "commit-sha",
			RuleDesc: "Warn if the action ref is not a full length commit SHA and not an official GitHub Action.",
		},
		githubToken: token,
	}
}

// Check if the given ref is a full length commit SHA
func isFullLengthSha(ref string) bool {
	re := regexp.MustCompile(`^.+@([0-9a-f]{40})$`)
	return re.MatchString(ref)
}

// VisitJobPre checks each step in each job for the action ref specifications
func (rule *CommitSha) VisitStep(step *ast.Step) error {
	if action, ok := step.Exec.(*ast.ExecAction); ok {
		usesValue := action.Uses.Value
		// Skip local action references (e.g., ./my-action). Local actions are part of the
		// same repository and are checked out at the same commit as the workflow, so they
		// have no supply chain risk and do not need commit SHA pinning.
		if strings.HasPrefix(usesValue, "./") {
			return nil
		}
		if !isFullLengthSha(usesValue) {
			rule.Errorf(step.Pos,
				"the action ref in 'uses' for step '%s' should be a full length commit SHA for immutability and security. See https://sisaku-security.github.io/lint/docs/rules/commitsharule/",
				step.String())
			rule.AddAutoFixer(NewStepFixer(step, rule)) // add autofix for this CommitSha rule
		}
	}
	return nil
}

// from https://github.com/suzuki-shunsuke/pinact/blob/532aa7ba57db6c11937831f993b51640bbda94ac/pkg/controller/run/parse_line.go#L18-L19
var (
	semverPattern   = regexp.MustCompile(`^v?\d+\.\d+\.\d+[^ ]*$`)
	shortTagPattern = regexp.MustCompile(`^v\d+$`)
)

func getLongVersion(cl *github.Client, owner, repo, sha string, expectedTag string) (string, error) {
	opts := &github.ListOptions{
		PerPage: 100,
	}
	for i := 0; i < 10; i++ {
		tags, resp, err := cl.Repositories.ListTags(context.Background(), owner, repo, opts)
		if err != nil {
			return "", fmt.Errorf("failed to list tags: %w", err)
		}
		for _, tag := range tags {
			if tag.GetCommit().GetSHA() == sha {
				tagName := tag.GetName()
				if strings.HasPrefix(tagName, expectedTag) {
					return tagName, nil
				}
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return "", nil
}

func (rule *CommitSha) githubClient() *github.Client {
	rule.clientOnce.Do(func() {
		rule.client = NewGitHubClient(context.Background(), rule.githubToken)
	})
	return rule.client
}

func (rule *CommitSha) FixStep(step *ast.Step) error {
	// at here, we can assume that the action ref is not a full length commit SHA
	action := step.Exec.(*ast.ExecAction)
	usesValue := action.Uses.Value
	gh := rule.githubClient()
	splitTag := strings.Split(usesValue, "@")
	if len(splitTag) != 2 {
		// Create a LintingError with position information
		lintErr := FormattedError(step.Pos, rule.RuleName, "invalid action reference format: '%s', expected format is 'owner/repo@ref'", usesValue)
		return lintErr
	}
	ownerRepo := strings.Split(splitTag[0], "/")
	if len(ownerRepo) != 2 {
		// Create a LintingError with position information
		lintErr := FormattedError(step.Pos, rule.RuleName, "invalid action owner/repo format: '%s', expected format is 'owner/repo'", splitTag[0])
		return lintErr
	}
	tag := splitTag[1]
	isSemver := semverPattern.MatchString(splitTag[1])
	isShortTag := shortTagPattern.MatchString(splitTag[1])
	//tagComment := action.Uses.BaseNode.LineComment
	sha, _, err := gh.Repositories.GetCommitSHA1(context.TODO(), ownerRepo[0], ownerRepo[1], tag, "")
	if err != nil {
		return rule.wrapAPIError(step, "failed to get commit SHA1", err)
	}
	if !isSemver && isShortTag {
		longVersion, err := getLongVersion(gh, ownerRepo[0], ownerRepo[1], sha, splitTag[1])
		if err != nil {
			return rule.wrapAPIError(step, "failed to get long version", err)
		}
		tag = longVersion
	}
	action.Uses.BaseNode.Value = splitTag[0] + "@" + sha
	action.Uses.BaseNode.LineComment = tag
	return nil
}

// wrapAPIError wraps rate-limit failures with ErrGitHubRateLimit so the
// caller can skip writing a partially-fixed workflow (issue #474).
func (rule *CommitSha) wrapAPIError(step *ast.Step, prefix string, err error) error {
	if IsGitHubRateLimitError(err) {
		lintErr := FormattedError(step.Pos, rule.RuleName,
			"%s: %s at step '%s' (set GITHUB_TOKEN, GH_TOKEN, SISAKULINT_GITHUB_TOKEN, or pass -github-token to lift the unauthenticated 60 req/h limit)",
			prefix, err.Error(), step.String())
		return fmt.Errorf("%w: %w", ErrGitHubRateLimit, lintErr)
	}
	return FormattedError(step.Pos, rule.RuleName, "%s: %s at step '%s'", prefix, err.Error(), step.String())
}
