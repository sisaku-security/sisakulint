package core

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// dependabotFindProjectRoot finds the project root directory by walking up from the
// workflow file path until a .github directory is found. Returns "" when the workflow
// directory does not exist on the local filesystem (e.g. remote-scan virtual paths) or
// when no .github directory is found.
func dependabotFindProjectRoot(workflowPath string) string {
	absPath, err := filepath.Abs(workflowPath)
	if err != nil {
		return ""
	}
	dir := filepath.Dir(absPath)
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	for {
		githubDir := filepath.Join(dir, ".github")
		if info, err := os.Stat(githubDir); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// dependabotFindConfigFile returns the path to the dependabot config file
// (.github/dependabot.yaml or dependabot.yml), or "" if neither exists.
func dependabotFindConfigFile(projectRoot string) string {
	yamlPath := filepath.Join(projectRoot, ".github", "dependabot.yaml")
	if _, err := os.Stat(yamlPath); err == nil {
		return yamlPath
	}
	ymlPath := filepath.Join(projectRoot, ".github", "dependabot.yml")
	if _, err := os.Stat(ymlPath); err == nil {
		return ymlPath
	}
	return ""
}

// dependabotConfiguredEcosystems parses the dependabot config at path and returns the set
// of configured package-ecosystem values.
func dependabotConfiguredEcosystems(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config dependabotConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(config.Updates))
	for _, update := range config.Updates {
		if update.PackageEcosystem != "" {
			result[update.PackageEcosystem] = true
		}
	}
	return result, nil
}

// renovateConfigCandidates returns the candidate Renovate config file paths for projectRoot.
func renovateConfigCandidates(projectRoot string) []string {
	return []string{
		filepath.Join(projectRoot, ".github", "renovate.json"),
		filepath.Join(projectRoot, ".github", "renovate.json5"),
		filepath.Join(projectRoot, "renovate.json"),
		filepath.Join(projectRoot, "renovate.json5"),
		filepath.Join(projectRoot, ".renovaterc"),
		filepath.Join(projectRoot, ".renovaterc.json"),
	}
}

// renovateManagesDependencies reports whether a Renovate config exists that manages package
// dependencies, via a broad preset (config:recommended / config:base / config:best-practices)
// or any packageRules.matchManagers entry. Best-effort skip condition for
// DependabotEcosystemRule.
func renovateManagesDependencies(projectRoot string) bool {
	knownPresets := []string{"config:recommended", "config:base", "config:best-practices"}
	for _, path := range renovateConfigCandidates(projectRoot) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg renovateConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}
		for _, r := range cfg.PackageRules {
			if len(r.MatchManagers) > 0 {
				return true
			}
		}
		for _, ext := range cfg.Extends {
			for _, preset := range knownPresets {
				if ext == preset {
					return true
				}
			}
		}
	}
	return false
}
