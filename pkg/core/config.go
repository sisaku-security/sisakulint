package core

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Configはsisakulintの設定を表す構造体でのインスタンスは".github"に位置する"sisakulint.yml"を読み込んでparse
type Config struct {
	//selfhostedrunner : setting for self-hosted runner
	SelfHostedRunner struct {
		//Labelsはself-hosted runnerのラベル
		Labels []string `yaml:"labels"`
	} `yaml:"self-hosted-runner"`
	// ConfigVariablesはチェックされるworkflowで使用される設定変数の名前を示す
	//この値がnilの時にvarsのコンテキストのプロパティ名はチェックされない
	ConfigVariables []string `yaml:"config-variables"`
	// ActionList は許可アクションのリストを管理する設定
	ActionList []string `yaml:"action-list"`

	// SecretExfiltration はsecret-exfiltrationルールのオプションを持つ
	// AllowedHosts は誤検知を抑制するためのhost allowlist (exact match or "*." suffix wildcard, case-insensitive)
	SecretExfiltration SecretExfiltrationConfig `yaml:"secret-exfiltration"`

	actionListRegex []*regexp.Regexp
}

// SecretExfiltrationConfig holds rule-specific configuration for the
// secret-exfiltration rule. AllowedHosts accepts exact host names
// (e.g. "api.example.com") and suffix wildcards of the form "*.example.com".
// Regex / glob syntax is intentionally not supported; this keeps the
// allowlist semantics easy to reason about and audit.
type SecretExfiltrationConfig struct {
	AllowedHosts []string `yaml:"allowed-hosts"`
}

// Stringはfmt.Stringerインターフェースを実装し、Configを読みやすい形式で出力する
func (c *Config) String() string {
	var parts []string

	if len(c.SelfHostedRunner.Labels) > 0 {
		parts = append(parts, fmt.Sprintf("self-hosted-runner.labels: %v", c.SelfHostedRunner.Labels))
	}

	if len(c.ConfigVariables) > 0 {
		parts = append(parts, fmt.Sprintf("config-variables: %v", c.ConfigVariables))
	}

	if len(c.ActionList) > 0 {
		parts = append(parts, fmt.Sprintf("action-list: %v", c.ActionList))
	}

	if len(c.SecretExfiltration.AllowedHosts) > 0 {
		parts = append(parts, fmt.Sprintf("secret-exfiltration.allowed-hosts: %v", c.SecretExfiltration.AllowedHosts))
	}

	if len(parts) == 0 {
		return "Config{empty}"
	}

	return "Config{" + strings.Join(parts, ", ") + "}"
}

// parseConfigは与えられたbyte sliceをConfigにparseする
func parseConfig(b []byte, path string) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		msg := strings.ReplaceAll(err.Error(), "\n", " ")
		return nil, fmt.Errorf("failed to parse config file %q: %s", path, msg)
	}
	// ActionListのパターンをコンパイル
	for _, pattern := range c.ActionList {
		re, err := compileActionPattern(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex for action list %q: %w", pattern, err)
		}
		c.actionListRegex = append(c.actionListRegex, re)
	}
	return &c, nil
}

// ReadConfigFileは指定されたファイルパスからsisakulint.yamlを読み込む
func ReadConfigFile(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}
	return parseConfig(b, path)
}

// loadRepoConfigは、リポジトリ.github/sisakulint.yml or .github/sisakulint.ymlを読み込む
func loadRepoConfig(root string) (*Config, error) {
	for _, f := range []string{"sisakulint.yaml", "sisakulint.yml"} {
		path := filepath.Join(root, ".github", f)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		cfg, err := parseConfig(b, path)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}
	return nil, nil
}

// writeDefaultConfigFileは指定されたファイルパスにデフォルトの設定ファイルを書き込む
func writeDefaultConfigFile(path string) error {
	b := []byte(`# Configuration file for sisakulint
# Use this file to customize the behavior of sisakulint

# self-hosted-runner section is for configuring self-hosted runners.
self-hosted-runner:
  # Labels of the self-hosted runners used in your project, as an array of strings.
  # 🧠 Example: labels: ["linux-large", "windows-2xlarge"]
  labels: []

# config-variables section is for specifying configuration variables defined in your repository or organization.
# Setting it to null disables the check for configuration variables.
# An empty array means no configuration variable is allowed.
# 🧠 Example: config-variables: ["CI_ENVIRONMENT", "DEPLOY_TARGET"]
# Note: List all the configuration variables that are used in your GitHub Actions workflows.
config-variables: null

# action-list section is an allowlist of the actions that may appear in "uses:".
# When it is empty or omitted, the action-list rule reports nothing.
# When it has one or more patterns, every "uses:" value that matches none of them is reported.
# The whole "uses:" value is matched, including the part after "@", and "*" stands for any
# string. So "actions/checkout" does NOT match "actions/checkout@v4"; write "actions/checkout@*".
# 🧠 Example:
# action-list:
#   - actions/checkout@*
#   - actions/setup-node@*
action-list: []

# secret-exfiltration section configures the secret-exfiltration rule.
# allowed-hosts suppresses findings whose destination hostname matches any
# entry. Supported syntax:
#   - "api.example.com"  -> exact host match (case-insensitive)
#   - "*.example.com"    -> matches any subdomain (sub.example.com,
#                          api.sub.example.com) but NOT the apex
#                          (example.com) (case-insensitive). To allow the
#                          apex too, list "example.com" as a separate entry.
# Only a leading "*." wildcard is supported. Other regex / glob syntax,
# schemes, paths, and ports are rejected.
# 🧠 Example:
# secret-exfiltration:
#   allowed-hosts:
#     - api.example.com
#     - "*.example.com"
secret-exfiltration:
  allowed-hosts: []
`)
	if err := os.WriteFile(path, b, 0644); err != nil { //nolint:gosec // config file is committed to git and must be readable by CI
		return fmt.Errorf("failed to write config file %q: %w", path, err)
	}
	return nil
}
