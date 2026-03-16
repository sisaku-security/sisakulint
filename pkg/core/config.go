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

	actionListRegex []*regexp.Regexp
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
	b := []byte(`
# Configuration file for sisakulint
# Use this file to customize the behavior of sisakulint
# self-hosted-runner section is for configuring self-hosted runners.
self-hosted-runner:
  # Use the labels key to specify labels for self-hosted runners used in your project as an array of strings.
  # This allows sisakulint to verify that these labels are correctly configured.
  # 🧠 Example: labels: ["linux-large", "windows-2xlarge"]
  # Note: Ensure that the labels match those configured in your self-hosted runner settings.
  labels: []

# config-variables section is for specifying configuration variables defined in your repository or organization.
# Setting it to null disables the check for configuration variables.
# An empty array means no configuration variable is allowed.
# 🧠 Example: config-variables: ["CI_ENVIRONMENT", "DEPLOY_TARGET"]
# Note: List all the configuration variables that are used in your GitHub Actions workflows.
config-variables: null

# action-list section is for specifying which GitHub Actions are allowed or blocked in your workflows.
# You can define a whitelist (only these actions are allowed) or a blacklist (these actions are blocked).
# Using wildcards is supported: actions/checkout@* matches any version of actions/checkout.
action-list:
  whitelist:
    - actions/checkout@*
    - actions/setup-node@*
    - actions/cache@*
  blacklist:
    - untrusted/*@*
    - suspicious/*@*

# Add other optional settings below.
# 🧠 Example: some-option: value
# Note: Refer to the sisakulint documentation for more information on available settings.
	`)
	if err := os.WriteFile(path, b, 0644); err != nil { //nolint:gosec // config file is committed to git and must be readable by CI
		return fmt.Errorf("failed to write config file %q: %w", path, err)
	}
	return nil
}
