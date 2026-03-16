package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// ActionListGenerator は既存のワークフローファイルからアクションリストを生成する
type ActionListGenerator struct {
	actions map[string]bool // 重複を避けるためのセット
}

// NewActionListGenerator は新しいActionListGeneratorを作成
func NewActionListGenerator() *ActionListGenerator {
	return &ActionListGenerator{
		actions: make(map[string]bool),
	}
}

// CollectActionsFromWorkflow はワークフローファイルからアクション参照を収集
func (g *ActionListGenerator) CollectActionsFromWorkflow(workflow *ast.Workflow) {
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if action, ok := step.Exec.(*ast.ExecAction); ok {
				usesValue := action.Uses.Value
				if usesValue != "" {
					// バージョン部分をワイルドカードに変換してパターン化
					pattern := g.normalizeActionPattern(usesValue)
					g.actions[pattern] = true
				}
			}
		}
	}
}

// normalizeActionPattern はアクション参照をパターンに正規化
// 例: "actions/checkout@v4" -> "actions/checkout@*"
func (g *ActionListGenerator) normalizeActionPattern(actionRef string) string {
	// @ で分割してバージョン部分を取得
	parts := strings.Split(actionRef, "@")
	if len(parts) != 2 {
		// @ がない場合はそのまま返す
		return actionRef
	}

	owner := parts[0]

	// ローカルパス（./や../で始まる）の場合はそのまま返す
	if strings.HasPrefix(owner, "./") || strings.HasPrefix(owner, "../") {
		return actionRef
	}

	// docker:// で始まる場合もそのまま返す
	if strings.HasPrefix(actionRef, "docker://") {
		return actionRef
	}

	// バージョンをワイルドカードに置き換え
	return owner + "@*"
}

// GetSortedActions は収集したアクションをソート済みのスライスとして返す
func (g *ActionListGenerator) GetSortedActions() []string {
	actions := make([]string, 0, len(g.actions))
	for action := range g.actions {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return actions
}

// GenerateActionListConfig は既存のワークフローファイルからaction-list設定を生成
func GenerateActionListConfig(root string) error {
	// .github/workflows ディレクトリを探す
	workflowsDir := filepath.Join(root, ".github", "workflows")
	if _, err := os.Stat(workflowsDir); os.IsNotExist(err) {
		return fmt.Errorf(".github/workflows directory not found at %s", workflowsDir)
	}

	// ワークフローファイルを探す
	files, err := filepath.Glob(filepath.Join(workflowsDir, "*.y*ml"))
	if err != nil {
		return fmt.Errorf("failed to find workflow files: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no workflow files found in %s", workflowsDir)
	}

	// アクションを収集
	generator := NewActionListGenerator()
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to read %s: %v\n", file, err)
			continue
		}

		// ワークフローをパース
		workflow, errs := Parse(content)
		if len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse workflow from %s: %v\n", file, errs[0])
			continue
		}
		if workflow == nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse workflow from %s\n", file)
			continue
		}

		generator.CollectActionsFromWorkflow(workflow)
	}

	actions := generator.GetSortedActions()
	if len(actions) == 0 {
		return fmt.Errorf("no actions found in workflow files")
	}

	// 設定ファイルに書き込む
	configPath := filepath.Join(root, ".github", "sisakulint.yaml")

	// 既存の設定ファイルがある場合は読み込む
	var existingConfig *Config
	if content, err := os.ReadFile(configPath); err == nil {
		existingConfig, _ = parseConfig(content, configPath)
	}

	// YAML形式で出力
	var buf strings.Builder
	buf.WriteString("# Configuration file for sisakulint\n")
	buf.WriteString("# Auto-generated action list from existing workflow files\n")
	buf.WriteString("\n")

	if existingConfig != nil && len(existingConfig.SelfHostedRunner.Labels) > 0 {
		buf.WriteString("self-hosted-runner:\n")
		buf.WriteString("  labels:\n")
		for _, label := range existingConfig.SelfHostedRunner.Labels {
			buf.WriteString(fmt.Sprintf("    - %s\n", label))
		}
		buf.WriteString("\n")
	}

	if existingConfig != nil && existingConfig.ConfigVariables != nil {
		buf.WriteString("config-variables:\n")
		if len(existingConfig.ConfigVariables) == 0 {
			buf.WriteString("  []\n")
		} else {
			for _, v := range existingConfig.ConfigVariables {
				buf.WriteString(fmt.Sprintf("  - %s\n", v))
			}
		}
		buf.WriteString("\n")
	}

	buf.WriteString("# Allowed GitHub Actions (auto-generated from existing workflows)\n")
	buf.WriteString("action-list:\n")
	for _, action := range actions {
		buf.WriteString(fmt.Sprintf("  - %s\n", action))
	}

	if err := os.WriteFile(configPath, []byte(buf.String()), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Generated action list configuration at %s\n", configPath)
	fmt.Printf("Found %d unique action patterns\n", len(actions))

	return nil
}
