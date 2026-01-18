package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

type ArchivedUsesRule struct {
	BaseRule
	archivedRepos map[string]struct{}
}

func NewArchivedUsesRule() *ArchivedUsesRule {
	rule := &ArchivedUsesRule{
		BaseRule: BaseRule{
			RuleName: "archived-uses",
			RuleDesc: "Detects usage of actions/reusable workflows from archived repositories that are no longer maintained",
		},
	}
	rule.initArchivedReposList()
	return rule
}

// Based on: https://github.com/zizmorcore/zizmor/blob/main/support/archived-action-repos.txt
func (rule *ArchivedUsesRule) initArchivedReposList() {
	archivedRepos := []string{
		// Official actions
		"actions/upload-release-asset",
		"actions/create-release",
		"actions/setup-ruby",
		"actions/setup-elixir",
		"actions/setup-haskell",

		// actions-rs (Rust)
		"actions-rs/cargo",
		"actions-rs/grcov",
		"actions-rs/audit-check",
		"actions-rs/toolchain",
		"actions-rs/tarpaulin",
		"actions-rs/clippy-check",
		"actions-rs/install",
		"actions-rs/components-nightly",

		// Community actions
		"andrewmcodes-archive/rubocop-linter-action",
		"artichoke/setup-rust",
		"aslafy-z/conventional-pr-title-action",

		// Azure actions
		"Azure/AppConfiguration-Sync",
		"Azure/appservice-actions",
		"Azure/azure-resource-login-action",
		"Azure/container-actions",
		"Azure/container-scan",
		"Azure/get-keyvault-secrets",
		"Azure/k8s-actions",
		"Azure/manage-azure-policy",
		"Azure/data-factory-deploy-action",
		"Azure/data-factory-export-action",
		"Azure/data-factory-validate-action",
		"Azure/publish-security-assessments",
		"Azure/run-sqlpackage-action",
		"Azure/spring-cloud-deploy",
		"Azure/webapps-container-deploy",

		// Other community actions
		"cedrickring/golang-action",
		"cirrus-actions/rebase",
		"crazy-max/ghaction-docker-buildx",
		"Decathlon/pull-request-labeler-action",
		"DeLaGuardo/setup-graalvm",
		"dulvui/godot-android-export",
		"expo/expo-preview-action",
		"fabasoad/setup-zizmor-action",
		"facebook/pysa-action",
		"fregante/release-with-changelog",
		"google/mirror-branch-action",
		"google/skywater-pdk-actions",
		"gradle/gradle-build-action",
		"grafana/k6-action",
		"helaili/github-graphql-action",
		"helaili/jekyll-action",
		"Ilshidur/action-slack",
		"jakejarvis/backblaze-b2-action",
		"jakejarvis/cloudflare-purge-action",
		"jakejarvis/firebase-deploy-action",
		"jakejarvis/hugo-build-action",
		"jakejarvis/lighthouse-action",
		"jakejarvis/s3-sync-action",
		"justinribeiro/lighthouse-action",
		"kanadgupta/glitch-sync",
		"kxxt/chatgpt-action",
		"machine-learning-apps/wandb-action",
		"MansaGroup/gcs-cache-action",
		"marvinpinto/actions",
		"marvinpinto/action-automatic-releases",
		"maxheld83/ghpages",
		"micnncim/action-lgtm-reaction",
		"mikepenz/gradle-dependency-submission",
		"orf/cargo-bloat-action",
		"paambaati/codeclimate-action",
		"primer/figma-action",
		"repo-sync/pull-request",
		"repo-sync/repo-sync",
		"sagebind/docker-swarm-deploy-action",
		"ScottBrenner/generate-changelog-action",
		"secrethub/actions",
		"semgrep/semgrep-action",
		"ShaunLWM/action-release-debugapk",
		"stefanprodan/kube-tools",
		"SonarSource/sonarcloud-github-action",
		"SwiftDocOrg/github-wiki-publish-action",
		"tachiyomiorg/issue-moderator-action",
		"technote-space/auto-cancel-redundant-workflow",
		"technote-space/get-diff-action",
		"TencentCloudBase/cloudbase-action",
		"trmcnvn/chrome-addon",
		"whelk-io/maven-settings-xml-action",
		"yeslayla/build-godot-action",
		"youyo/aws-cdk-github-actions",
		"z0al/dependent-issues",
		"8398a7/action-slack",
	}

	rule.archivedRepos = make(map[string]struct{}, len(archivedRepos))
	for _, repo := range archivedRepos {
		rule.archivedRepos[strings.ToLower(repo)] = struct{}{}
	}
}

func (rule *ArchivedUsesRule) isArchivedRepo(owner, repo string) bool {
	key := strings.ToLower(owner + "/" + repo)
	_, exists := rule.archivedRepos[key]
	return exists
}

func parseUsesValue(uses string) (owner, repo, ref string) {
	if strings.HasPrefix(uses, "./") {
		return "", "", ""
	}
	if strings.HasPrefix(uses, "docker://") {
		return "", "", ""
	}

	atIndex := strings.LastIndex(uses, "@")
	if atIndex == -1 {
		atIndex = len(uses)
	} else {
		ref = uses[atIndex+1:]
	}

	repoPath := uses[:atIndex]
	parts := strings.Split(repoPath, "/")
	if len(parts) < 2 {
		return "", "", ""
	}

	owner = parts[0]
	repo = parts[1]
	return owner, repo, ref
}

func (rule *ArchivedUsesRule) VisitStep(step *ast.Step) error {
	if action, ok := step.Exec.(*ast.ExecAction); ok {
		usesValue := action.Uses.Value
		owner, repo, _ := parseUsesValue(usesValue)

		if owner != "" && repo != "" && rule.isArchivedRepo(owner, repo) {
			rule.Errorf(action.Uses.Pos,
				"action '%s/%s' is from an archived repository and is no longer maintained. "+
					"Archived actions may have unpatched security vulnerabilities and should be replaced with maintained alternatives. "+
					"See: https://github.com/%s/%s",
				owner, repo, owner, repo)
		}
	}
	return nil
}

func (rule *ArchivedUsesRule) VisitJobPre(job *ast.Job) error {
	if job.WorkflowCall != nil && job.WorkflowCall.Uses != nil {
		usesValue := job.WorkflowCall.Uses.Value
		owner, repo, _ := parseUsesValue(usesValue)

		if owner != "" && repo != "" && rule.isArchivedRepo(owner, repo) {
			rule.Errorf(job.WorkflowCall.Uses.Pos,
				"reusable workflow '%s/%s' is from an archived repository and is no longer maintained. "+
					"Archived repositories may have unpatched security vulnerabilities and should be replaced with maintained alternatives. "+
					"See: https://github.com/%s/%s",
				owner, repo, owner, repo)
		}
	}
	return nil
}
