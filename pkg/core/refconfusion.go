package core

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// RefConfusion detects ref confusion vulnerabilities where both a branch and tag
// with the same name exist, which can lead to supply chain attacks.
type RefConfusion struct {
	BaseRule
	// cache for ref confusion check results to avoid repeated API calls
	refCache     map[string]bool
	refCacheMu   sync.Mutex
	ghClient     *github.Client
	ghClientOnce sync.Once
}

// NewRefConfusionRule creates a new RefConfusion rule instance.
func NewRefConfusionRule() *RefConfusion {
	return &RefConfusion{
		BaseRule: BaseRule{
			RuleName: "ref-confusion",
			RuleDesc: "Detects actions using refs that exist as both a branch and tag, which can lead to supply chain attacks.",
		},
		refCache: make(map[string]bool),
	}
}

// shaPattern is a pre-compiled regex for 40-character lowercase hex SHA.
var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func isSymbolicRef(ref string) bool {
	return !shaPattern.MatchString(ref)
}

func parseActionRefForRefConfusion(usesValue string) (owner, repo, ref string, ok bool) {
	// Skip local actions
	if strings.HasPrefix(usesValue, "./") {
		return "", "", "", false
	}
	// Skip Docker references
	if strings.HasPrefix(usesValue, "docker://") {
		return "", "", "", false
	}

	parts := strings.Split(usesValue, "@")
	if len(parts) != 2 {
		return "", "", "", false
	}

	ref = parts[1]
	ownerRepoPath := parts[0]

	pathParts := strings.Split(ownerRepoPath, "/")
	if len(pathParts) < 2 {
		return "", "", "", false
	}

	owner = pathParts[0]
	repo = pathParts[1]

	return owner, repo, ref, true
}

func (rule *RefConfusion) getGitHubClient() *github.Client {
	rule.ghClientOnce.Do(func() {
		rule.ghClient = github.NewClient(http.DefaultClient)
	})
	return rule.ghClient
}

func (rule *RefConfusion) hasBranch(ctx context.Context, owner, repo, branchName string) (bool, error) {
	client := rule.getGitHubClient()
	_, resp, err := client.Repositories.GetBranch(ctx, owner, repo, branchName, 0)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (rule *RefConfusion) hasTag(ctx context.Context, owner, repo, tagName string) (bool, error) {
	client := rule.getGitHubClient()
	_, resp, err := client.Git.GetRef(ctx, owner, repo, "tags/"+tagName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (rule *RefConfusion) isConfusable(owner, repo, ref string) (bool, error) {
	cacheKey := owner + "/" + repo + "@" + ref

	rule.refCacheMu.Lock()
	if result, ok := rule.refCache[cacheKey]; ok {
		rule.refCacheMu.Unlock()
		return result, nil
	}
	rule.refCacheMu.Unlock()

	ctx := context.Background()

	hasBranch, err := rule.hasBranch(ctx, owner, repo, ref)
	if err != nil {
		rule.Debug("failed to check branch existence for %s/%s@%s: %v", owner, repo, ref, err)
		return false, nil
	}

	if !hasBranch {
		rule.refCacheMu.Lock()
		rule.refCache[cacheKey] = false
		rule.refCacheMu.Unlock()
		return false, nil
	}

	hasTag, err := rule.hasTag(ctx, owner, repo, ref)
	if err != nil {
		rule.Debug("failed to check tag existence for %s/%s@%s: %v", owner, repo, ref, err)
		return false, nil
	}

	confusable := hasBranch && hasTag

	rule.refCacheMu.Lock()
	rule.refCache[cacheKey] = confusable
	rule.refCacheMu.Unlock()

	return confusable, nil
}

func (rule *RefConfusion) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	usesValue := action.Uses.Value

	owner, repo, ref, ok := parseActionRefForRefConfusion(usesValue)
	if !ok {
		return nil
	}

	if !isSymbolicRef(ref) {
		return nil
	}

	confusable, err := rule.isConfusable(owner, repo, ref)
	if err != nil {
		rule.Debug("error checking ref confusion for %s: %v", usesValue, err)
		return nil
	}

	if confusable {
		rule.Errorf(step.Pos,
			"action '%s' uses ref '%s' which exists as both a branch and a tag in %s/%s. "+
				"This can lead to supply chain attacks if an attacker creates a branch with the same name as a tag. "+
				"Consider pinning to a full commit SHA for security. See https://sisaku-security.github.io/lint/docs/rules/refconfusion/",
			usesValue, ref, owner, repo)
		rule.AddAutoFixer(NewStepFixer(step, rule))
	}

	return nil
}

func (rule *RefConfusion) VisitJobPre(node *ast.Job) error {
	return nil
}

func (rule *RefConfusion) VisitJobPost(node *ast.Job) error {
	return nil
}

func (rule *RefConfusion) VisitWorkflowPre(node *ast.Workflow) error {
	return nil
}

func (rule *RefConfusion) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

func (rule *RefConfusion) FixStep(step *ast.Step) error {
	action := step.Exec.(*ast.ExecAction)
	usesValue := action.Uses.Value

	owner, repo, ref, ok := parseActionRefForRefConfusion(usesValue)
	if !ok {
		return FormattedError(step.Pos, rule.RuleName, "invalid action reference format: '%s'", usesValue)
	}

	client := rule.getGitHubClient()
	sha, _, err := client.Repositories.GetCommitSHA1(context.Background(), owner, repo, ref, "")
	if err != nil {
		return FormattedError(step.Pos, rule.RuleName, "failed to get commit SHA for %s/%s@%s: %s", owner, repo, ref, err.Error())
	}

	atIdx := strings.Index(usesValue, "@")
	if atIdx == -1 {
		return FormattedError(step.Pos, rule.RuleName, "invalid action reference format: '%s'", usesValue)
	}
	ownerRepoPath := usesValue[:atIdx]

	action.Uses.BaseNode.Value = ownerRepoPath + "@" + sha
	action.Uses.BaseNode.LineComment = ref

	return nil
}
