package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Boilerはsisakulintの設定を表す構造体でのインスタンスは".github"に位置する"boilerplate.yml"を読み込んでparse
type Boiler struct {
	//selfhostedrunner : setting for self-hosted runner
	SelfHostedRunner struct {
		//Labelsはself-hosted runnerのラベル
		Labels []string `yaml:"labels"`
	} `yaml:"self-hosted-runner"`
	// ConfigVariablesはチェックされるworkflowで使用される設定変数の名前を示す
	//この値がnilの時にvarsのコンテキストのプロパティ名はチェックされない
	ConfigVariables []string `yaml:"config-variables"`
}

// parseBoilerは与えられたbyte sliceをConfigにparseする
func parseBoiler(b []byte, path string) (*Boiler, error) {
	var c Boiler
	if err := yaml.Unmarshal(b, &c); err != nil {
		msg := strings.ReplaceAll(err.Error(), "\n", " ")
		return nil, fmt.Errorf("failed to parse boilerplate file %q: %s", path, msg)
	}
	return &c, nil
}

// ReadBoilerは指定されたファイルパスからboilerplate.yamlを読み込む
func ReadBoiler(path string) (*Boiler, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read boilerplate file %q: %w", path, err)
	}
	return parseBoiler(b, path)
}

// loadBoilerは.github/boilerplate.yml or .github/boilerplate.ymlを読み込む
func loadBoiler(root string) (*Boiler, error) {
	for _, f := range []string{"boilerplate.yaml", "boilerplate.yml"} {
		path := filepath.Join(root, ".github", f)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		cfg, err := parseBoiler(b, path)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}
	return nil, nil
}

// writeDefaultBoilerplateFileは指定されたファイルパスにデフォルトの設定ファイルを書き込む
func writeDefaultBoilerplateFile(path string) error {
	b := []byte(`
# costom boilerplate file from sisakulint
name: sample deploy to GitHub Pages

on:
  # Trigger the workflow every time you push to the main branch
  # Using a different branch name? Replace main with your branch’s name
  push:
    branches: [main]
  # Allows you to run this workflow manually from the Actions tab on GitHub.
  workflow_dispatch:

# Allow this job to clone the repo and create a page deployment
permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout your repository using git
	  	# Recommend to fix actions commit SHA
        uses: actions/checkout@v4
      - name: Install, build, and upload your site output
        uses: custom/custom@v1
        # with:
            # path: . # The root location of your Astro project inside the repository. (optional)
            # node-version: 18 # The specific version of Node that should be used to build your site. Defaults to 18. (optional)
            # package-manager: pnpm@latest # The Node package manager that should be used to install dependencies and build your site. Automatically detected based on your lockfile. (optional)

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v3
	`)
	if err := os.WriteFile(path, b, 0644); err != nil { //nolint:gosec // workflow files require group-readable permissions for git and CI
		return fmt.Errorf("failed to write config file %q: %w", path, err)
	}
	return nil
}
