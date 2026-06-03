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
// dependabot ecosystems that Renovate manages via packageRules.matchManagers and
// enabledManagers. The all return value is true when a broad preset (config:recommended /
// config:base / config:best-practices) is extended *and* the config does not narrow that
// scope via enabledManagers, which Renovate documents as restricting active managers to
// only those listed. Best-effort: unrecognized managers are ignored so a Renovate rule
// scoped to one ecosystem does not suppress warnings for the others.
func renovateManagedEcosystems(projectRoot string) (managed map[string]bool, all bool) {
	managed = map[string]bool{}
	knownPresets := []string{"config:recommended", "config:base", "config:best-practices"}
	var (
		hasBroadPreset            bool
		enabledManagersConstrains bool
	)
	for _, path := range renovateConfigCandidates(projectRoot) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg renovateConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			// Renovate accepts JSON5 (renovate.json5 and, in practice, .json/.renovaterc
			// files with // comments or trailing commas). yaml.v3 reads JSON but rejects
			// those JSON5 specifics, which would silently skip a broad-preset config and
			// produce false positives. Strip the JSON5 sugar and retry before giving up.
			cleaned := stripJSON5Sugar(data)
			if err := yaml.Unmarshal(cleaned, &cfg); err != nil {
				continue
			}
		}
		for _, ext := range cfg.Extends {
			for _, preset := range knownPresets {
				if ext == preset {
					hasBroadPreset = true
				}
			}
		}
		// enabledManagers restricts Renovate to the listed managers and disables the rest,
		// so the "broad preset enables every manager" assumption no longer holds. Record
		// each listed manager's ecosystem so a config like `enabledManagers: ["npm"]` still
		// suppresses npm warnings while leaving sibling ecosystems (cargo, etc.) to surface.
		if len(cfg.EnabledManagers) > 0 {
			enabledManagersConstrains = true
			for _, m := range cfg.EnabledManagers {
				if eco, ok := renovateManagerToEcosystem[m]; ok {
					managed[eco] = true
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
	all = hasBroadPreset && !enabledManagersConstrains
	return managed, all
}

// stripJSON5Sugar removes JSON5-specific syntax — // line comments, /* */ block comments,
// and trailing commas before ']' or '}' — from data so the result can be parsed by a JSON
// (or YAML-as-JSON-superset) parser. String literals delimited by " or ' are preserved
// verbatim, including escape sequences, so syntax inside strings is never touched.
// Best-effort: unquoted keys and other JSON5 features the YAML parser already tolerates
// are not normalized here.
func stripJSON5Sugar(data []byte) []byte {
	out := make([]byte, 0, len(data))
	n := len(data)
	inStr := false
	var strDelim byte
	for i := 0; i < n; {
		c := data[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < n {
				out = append(out, data[i+1])
				i += 2
				continue
			}
			if c == strDelim {
				inStr = false
			}
			i++
			continue
		}
		if c == '"' || c == '\'' {
			inStr = true
			strDelim = c
			out = append(out, c)
			i++
			continue
		}
		if c == '/' && i+1 < n && data[i+1] == '/' {
			for i < n && data[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < n && data[i+1] == '*' {
			i += 2
			for i+1 < n && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			if i+1 < n {
				i += 2
			} else {
				i = n
			}
			continue
		}
		if c == ',' {
			j := i + 1
			for j < n {
				w := data[j]
				if w == ' ' || w == '\t' || w == '\r' || w == '\n' {
					j++
					continue
				}
				break
			}
			if j < n && (data[j] == ']' || data[j] == '}') {
				i++
				continue
			}
		}
		out = append(out, c)
		i++
	}
	return out
}
