package core

import (
	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"gopkg.in/yaml.v3"
)

var allPermissionScopes = map[string]struct{}{
	"actions":             {},
	"attestations":        {},
	"checks":              {},
	"contents":            {},
	"deployments":         {},
	"discussions":         {},
	"id-token":            {},
	"issues":              {},
	"models":              {},
	"packages":            {},
	"pages":               {},
	"pull-requests":       {},
	"repository-projects": {},
	"security-events":     {},
	"statuses":            {},
}

// RulePermissions is a rule checker to check permission configurations in a workflow.
// * https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
// * https://codeql.github.com/codeql-query-help/actions/actions-missing-workflow-permissions/
type PermissionRule struct {
	BaseRule
	// isReusableWorkflow indicates if the workflow is a reusable workflow (has workflow_call event)
	// Reusable workflows inherit permissions from the caller, so missing permissions is not an error
	isReusableWorkflow bool
}

// PermissionsRule creates a new PermissionRule instance.
func PermissionsRule() *PermissionRule {
	return &PermissionRule{
		BaseRule: BaseRule{
			RuleName: "permissions",
			RuleDesc: "Checks for permissions configuration in \"permissions:\". Permission names and permission scopes are checked",
		},
	}
}

// VisitJobPre is callback when visiting Job node before visiting its children.
func (rule *PermissionRule) VisitJobPre(n *ast.Job) error {
	rule.checkPermissions(n.Permissions)
	return nil
}

// VisitWorkflowPre is callback when visiting Workflow node before visiting its children.
// It checks for missing permissions block and validates existing permissions.
func (rule *PermissionRule) VisitWorkflowPre(n *ast.Workflow) error {
	// Reset state for each workflow
	rule.isReusableWorkflow = false

	// Check if this is a reusable workflow (has workflow_call event)
	// Reusable workflows inherit permissions from the caller
	for _, event := range n.On {
		if _, ok := event.(*ast.WorkflowCallEvent); ok {
			rule.isReusableWorkflow = true
			break
		}
	}

	// Check for missing permissions block (CodeQL: actions-missing-workflow-permissions)
	// Skip this check for reusable workflows as they inherit permissions from caller
	if n.Permissions == nil && !rule.isReusableWorkflow {
		// Check if all jobs have explicit permissions defined
		// If all jobs have permissions, workflow-level permissions are not required
		allJobsHavePermissions := len(n.Jobs) > 0 // At least one job must exist
		for _, job := range n.Jobs {
			if job.Permissions == nil {
				allJobsHavePermissions = false
				break
			}
		}

		// Only report missing permissions if not all jobs have explicit permissions
		if !allJobsHavePermissions {
			pos := &ast.Position{Line: 1, Col: 1}
			if n.BaseNode != nil && n.BaseNode.Line > 0 {
				pos = &ast.Position{Line: n.BaseNode.Line, Col: n.BaseNode.Column}
			}
			rule.Errorf(pos,
				"workflow does not have explicit 'permissions' block. "+
					"Without explicit permissions, the workflow uses the default repository permissions which may be overly broad. "+
					"Add a 'permissions:' block to follow the principle of least privilege. "+
					"See https://sisaku-security.github.io/lint/docs/rules/permissions/")
			rule.AddAutoFixer(NewFuncFixer(rule.RuleNames(), func() error {
				return rule.fixMissingPermissions(n)
			}))
		}
	}

	rule.checkPermissions(n.Permissions)
	return nil
}

func (rule *PermissionRule) checkPermissions(p *ast.Permissions) {
	if p == nil {
		return
	}

	if p.All != nil {
		switch p.All.Value {
		case "write-all":
			rule.Errorf(
				p.All.Pos,
				"warning : The 'write-all' scope is too broad, covering all available scopes. Please specify 'write' or 'read' for each individual scope instead.Value: %s plaese see https://github.com/suzuki-shunsuke/ghalint/blob/main/docs/policies/003.md",
				p.All.Value,
			)
		case "read-all":
			// read-all is valid and secure - no warning needed
		default:
			rule.Errorf(p.All.Pos, "%q is invalid for permission for all the scopes.", p.All.Value)
		}
		return
	}

	for _, p := range p.Scopes {
		n := p.Name.Value // Permission names are case-sensitive
		if _, ok := allPermissionScopes[n]; !ok {
			ss := make([]string, 0, len(allPermissionScopes))
			for s := range allPermissionScopes {
				ss = append(ss, s)
			}
			rule.Errorf(p.Name.Pos, "unknown permission scope %q. all available permission scopes are %s", n, expressions.SortedQuotes(ss))
		}
		switch p.Value.Value {
		case "read", "write", "none":
			// OK
		default:
			rule.Errorf(
				p.Value.Pos,
				"The value %q is not a valid permission for the scope %q. Only 'read', 'write', or 'none' are acceptable values.",
				p.Value.Value,
				n,
			)
		}
	}
}

// fixMissingPermissions adds a 'permissions: {}' block to the workflow.
// This is the safest default that grants no permissions.
// A comment is added to remind the user to review and add required permissions.
func (rule *PermissionRule) fixMissingPermissions(n *ast.Workflow) error {
	if n.BaseNode == nil {
		return nil
	}

	// BaseNode is a DocumentNode, Content[0] is the MappingNode containing the workflow
	var mappingNode *yaml.Node
	if n.BaseNode.Kind == yaml.DocumentNode && len(n.BaseNode.Content) > 0 {
		mappingNode = n.BaseNode.Content[0]
	} else if n.BaseNode.Kind == yaml.MappingNode {
		mappingNode = n.BaseNode
	} else {
		return nil
	}

	// Find the best position to insert permissions block
	// Preferred order: after 'name', after 'on', or at the beginning
	insertIndex := 0
	for i := 0; i < len(mappingNode.Content); i += 2 {
		key := mappingNode.Content[i].Value
		if key == "name" || key == "run-name" {
			insertIndex = i + 2
		} else if key == "on" {
			insertIndex = i + 2
			break
		}
	}

	// Create permissions key node with NOTICE comment
	permissionsKeyNode := &yaml.Node{
		Kind:        yaml.ScalarNode,
		Value:       "permissions",
		HeadComment: "TODO: Review and add required permissions. Auto-fix sets empty (no permissions) for safety.",
	}

	// Create empty mapping node for permissions: {}
	// This grants no permissions - user must explicitly add what's needed
	permissionsValueNode := &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{},
	}

	// Insert at the determined position
	newContent := make([]*yaml.Node, 0, len(mappingNode.Content)+2)
	newContent = append(newContent, mappingNode.Content[:insertIndex]...)
	newContent = append(newContent, permissionsKeyNode, permissionsValueNode)
	newContent = append(newContent, mappingNode.Content[insertIndex:]...)
	mappingNode.Content = newContent

	return nil
}
