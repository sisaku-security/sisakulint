package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// SecretsInheritRule detects excessive secret inheritance using 'secrets: inherit' in reusable workflow calls.
// Using 'secrets: inherit' violates the Principle of Least Authority by passing all secrets
// to the called workflow instead of explicitly specifying only the required ones.
//
// Reference:
// - https://docs.zizmor.sh/audits/#secrets-inherit
// - https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-secrets-to-nested-workflows
type SecretsInheritRule struct {
	BaseRule
	cache *LocalReusableWorkflowCache
}

// NewSecretsInheritRule creates a new SecretsInheritRule instance.
func NewSecretsInheritRule() *SecretsInheritRule {
	return &SecretsInheritRule{
		BaseRule: BaseRule{
			RuleName: "secrets-inherit",
			RuleDesc: "Detects excessive secret inheritance using 'secrets: inherit' in reusable workflow calls",
		},
	}
}

// NewSecretsInheritRuleWithCache creates a new SecretsInheritRule instance with a cache for auto-fix.
func NewSecretsInheritRuleWithCache(cache *LocalReusableWorkflowCache) *SecretsInheritRule {
	rule := NewSecretsInheritRule()
	rule.cache = cache
	return rule
}

// VisitJobPre is called before visiting child nodes of a Job node.
func (rule *SecretsInheritRule) VisitJobPre(n *ast.Job) error {
	if n.WorkflowCall == nil {
		return nil
	}

	if !n.WorkflowCall.InheritSecrets {
		return nil
	}

	uses := n.WorkflowCall.Uses
	if uses == nil {
		return nil
	}

	rule.Errorf(
		uses.Pos,
		"using 'secrets: inherit' in workflow call %q violates the principle of least authority. "+
			"Explicitly specify only the secrets that are required by the called workflow instead of inheriting all secrets",
		uses.Value,
	)

	// Add auto-fixer
	fixer := rule.createAutoFixer(n)
	if fixer != nil {
		rule.AddAutoFixer(fixer)
	}

	return nil
}

// RuleNames returns the rule name for JobFixer interface.
func (rule *SecretsInheritRule) RuleNames() string {
	return rule.RuleName
}

// FixJob fixes the job by replacing 'secrets: inherit' with explicit secrets.
func (rule *SecretsInheritRule) FixJob(job *ast.Job) error {
	if job.WorkflowCall == nil {
		return nil
	}

	uses := job.WorkflowCall.Uses
	if uses == nil {
		return nil
	}

	// Check if it's a local workflow and try to get metadata
	if strings.HasPrefix(uses.Value, "./") && rule.cache != nil {
		metadata, err := rule.cache.FindMetadata(uses.Value)
		if err == nil && metadata != nil {
			return rule.fixWithMetadata(job, metadata)
		}
	}

	// For external workflows or when metadata is not available, use template
	return rule.fixWithTemplate(job)
}

// fixWithMetadata fixes the job using the called workflow's metadata.
func (rule *SecretsInheritRule) fixWithMetadata(job *ast.Job, metadata *ReusableWorkflowMetadata) error {
	job.WorkflowCall.InheritSecrets = false

	if len(metadata.Secrets) == 0 {
		// No secrets required, remove the secrets section entirely
		job.WorkflowCall.Secrets = nil
		return nil
	}

	// Build explicit secrets mapping based on required secrets
	job.WorkflowCall.Secrets = make(map[string]*ast.WorkflowCallSecret, len(metadata.Secrets))
	for name, secret := range metadata.Secrets {
		if secret != nil {
			job.WorkflowCall.Secrets[name] = &ast.WorkflowCallSecret{
				Name: &ast.String{
					Value: secret.Name,
					Pos:   job.WorkflowCall.Uses.Pos,
				},
				Value: &ast.String{
					Value: fmt.Sprintf("${{ secrets.%s }}", strings.ToUpper(name)),
					Pos:   job.WorkflowCall.Uses.Pos,
				},
			}
		}
	}

	return nil
}

// fixWithTemplate fixes the job using a template placeholder.
func (rule *SecretsInheritRule) fixWithTemplate(job *ast.Job) error {
	job.WorkflowCall.InheritSecrets = false
	job.WorkflowCall.Secrets = map[string]*ast.WorkflowCallSecret{
		"secret_name": {
			Name: &ast.String{
				Value: "SECRET_NAME",
				Pos:   job.WorkflowCall.Uses.Pos,
			},
			Value: &ast.String{
				Value: "${{ secrets.SECRET_NAME }}",
				Pos:   job.WorkflowCall.Uses.Pos,
			},
		},
	}

	return nil
}

// createAutoFixer creates an auto-fixer for the secrets: inherit issue.
func (rule *SecretsInheritRule) createAutoFixer(job *ast.Job) AutoFixer {
	return NewJobFixer(job, rule)
}
