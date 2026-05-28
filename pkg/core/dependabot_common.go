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

// renovateManagerToEcosystem maps Renovate manager names to the dependabot package-ecosystem
// they correspond to. Only managers relevant to DependabotEcosystemRule are listed; managers
// that do not map to a checked ecosystem (e.g. github-actions, dockerfile, nvm) are ignored so
// they do not suppress unrelated ecosystems.
var renovateManagerToEcosystem = map[string]string{
	"npm":              "npm",
	"gomod":            "gomod",
	"cargo":            "cargo",
	"bundler":          "bundler",
	"composer":         "composer",
	"pip_requirements": "pip",
	"pip_setup":        "pip",
	"pip-compile":      "pip",
	"poetry":           "pip",
	"pep621":           "pip",
	"setup-cfg":        "pip",
	"maven":            "maven",
	"maven-wrapper":    "maven",
	"gradle":           "gradle",
	"gradle-wrapper":   "gradle",
	"sbt":              "sbt",
}

// renovateManagedEcosystems inspects Renovate configs in projectRoot and returns the set of
// dependabot ecosystems that Renovate manages via packageRules.matchManagers. The all return
// value is true when a broad preset (config:recommended / config:base / config:best-practices)
// is extended, which enables every manager. Best-effort: unrecognized managers are ignored so
// a Renovate rule scoped to one ecosystem does not suppress warnings for the others.
func renovateManagedEcosystems(projectRoot string) (managed map[string]bool, all bool) {
	managed = map[string]bool{}
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
		for _, ext := range cfg.Extends {
			for _, preset := range knownPresets {
				if ext == preset {
					all = true
				}
			}
		}
		for _, r := range cfg.PackageRules {
			for _, m := range r.MatchManagers {
				if eco, ok := renovateManagerToEcosystem[m]; ok {
					managed[eco] = true
				}
			}
		}
	}
	return managed, all
}
