package core

import (
	"testing"
)

func TestNewKnownVulnerableActionsRule(t *testing.T) {
	rule := NewKnownVulnerableActionsRule()

	if rule.RuleName != "known-vulnerable-actions" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "known-vulnerable-actions")
	}
	if rule.RuleDesc == "" {
		t.Error("RuleDesc should not be empty")
	}
}

func TestParseActionRef(t *testing.T) {
	tests := []struct {
		name      string
		usesValue string
		wantOwner string
		wantRepo  string
		wantRef   string
		wantOK    bool
	}{
		{
			name:      "standard action ref",
			usesValue: "actions/checkout@v4",
			wantOwner: "actions",
			wantRepo:  "checkout",
			wantRef:   "v4",
			wantOK:    true,
		},
		{
			name:      "action with commit SHA",
			usesValue: "actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744",
			wantOwner: "actions",
			wantRepo:  "checkout",
			wantRef:   "f43a0e5ff2bd294095638e18286ca9a3d1956744",
			wantOK:    true,
		},
		{
			name:      "action with path",
			usesValue: "actions/aws/lambda@v1",
			wantOwner: "actions",
			wantRepo:  "aws",
			wantRef:   "v1",
			wantOK:    true,
		},
		{
			name:      "action with semver",
			usesValue: "actions/setup-node@v3.8.1",
			wantOwner: "actions",
			wantRepo:  "setup-node",
			wantRef:   "v3.8.1",
			wantOK:    true,
		},
		{
			name:      "no ref",
			usesValue: "actions/checkout",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantOK:    false,
		},
		{
			name:      "local action",
			usesValue: "./.github/actions/my-action",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantOK:    false,
		},
		{
			name:      "docker action",
			usesValue: "docker://alpine:latest",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantOK:    false,
		},
		{
			name:      "empty",
			usesValue: "",
			wantOwner: "",
			wantRepo:  "",
			wantRef:   "",
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, ref, ok := parseActionRef(tt.usesValue)
			if owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
			if ref != tt.wantRef {
				t.Errorf("ref = %q, want %q", ref, tt.wantRef)
			}
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
		})
	}
}

func TestIsLocalAction(t *testing.T) {
	tests := []struct {
		name      string
		usesValue string
		want      bool
	}{
		{"local action", "./.github/actions/my-action", true},
		{"local action with subfolder", "./actions/test", true},
		{"remote action", "actions/checkout@v4", false},
		{"docker action", "docker://alpine:latest", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLocalAction(tt.usesValue)
			if got != tt.want {
				t.Errorf("isLocalAction(%q) = %v, want %v", tt.usesValue, got, tt.want)
			}
		})
	}
}

func TestIsDockerAction(t *testing.T) {
	tests := []struct {
		name      string
		usesValue string
		want      bool
	}{
		{"docker action", "docker://alpine:latest", true},
		{"docker with tag", "docker://ghcr.io/owner/repo:v1", true},
		{"remote action", "actions/checkout@v4", false},
		{"local action", "./.github/actions/my-action", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDockerAction(tt.usesValue)
			if got != tt.want {
				t.Errorf("isDockerAction(%q) = %v, want %v", tt.usesValue, got, tt.want)
			}
		})
	}
}

func TestIsFullLengthCommitSHA(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want bool
	}{
		{"full SHA", "f43a0e5ff2bd294095638e18286ca9a3d1956744", true},
		{"full SHA with all digits", "0123456789012345678901234567890123456789", true},
		{"full SHA with all letters", "abcdefabcdefabcdefabcdefabcdefabcdefabcd", true},
		{"short SHA", "f43a0e5", false},
		{"tag", "v4", false},
		{"semver", "v3.8.1", false},
		{"empty", "", false},
		{"39 chars", "f43a0e5ff2bd294095638e18286ca9a3d195674", false},
		{"41 chars", "f43a0e5ff2bd294095638e18286ca9a3d19567441", false},
		{"uppercase", "F43A0E5FF2BD294095638E18286CA9A3D1956744", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFullLengthCommitSHA(tt.ref)
			if got != tt.want {
				t.Errorf("isFullLengthCommitSHA(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestIsVersionAffected(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		vulnRange string
		want      bool
	}{
		{
			name:      "simple less than",
			version:   "6.25.0",
			vulnRange: "< 6.25.1",
			want:      true,
		},
		{
			name:      "version at boundary is not affected",
			version:   "6.25.1",
			vulnRange: "< 6.25.1",
			want:      false,
		},
		{
			name:      "version above is not affected",
			version:   "6.26.0",
			vulnRange: "< 6.25.1",
			want:      false,
		},
		{
			name:      "range with lower and upper bound",
			version:   "3.3.10",
			vulnRange: ">= 3.0.0, < 3.3.12",
			want:      true,
		},
		{
			name:      "below range is not affected",
			version:   "2.9.0",
			vulnRange: ">= 3.0.0, < 3.3.12",
			want:      false,
		},
		{
			name:      "at upper bound is not affected",
			version:   "3.3.12",
			vulnRange: ">= 3.0.0, < 3.3.12",
			want:      false,
		},
		{
			name:      "with v prefix in version",
			version:   "v2.0.1",
			vulnRange: ">= 2.0.0, < 2.0.3",
			want:      true,
		},
		{
			name:      "empty range",
			version:   "1.0.0",
			vulnRange: "",
			want:      false,
		},
		{
			name:      "version 0",
			version:   "0.9.0",
			vulnRange: "< 1.0.0",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVersionAffected(tt.version, tt.vulnRange)
			if got != tt.want {
				t.Errorf("isVersionAffected(%q, %q) = %v, want %v", tt.version, tt.vulnRange, got, tt.want)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		v1   string
		v2   string
		want int
	}{
		{"equal versions", "1.0.0", "1.0.0", 0},
		{"v1 less than v2", "1.0.0", "1.0.1", -1},
		{"v1 greater than v2", "1.0.2", "1.0.1", 1},
		{"major version diff", "2.0.0", "1.0.0", 1},
		{"minor version diff", "1.1.0", "1.0.0", 1},
		{"two part vs three part", "1.0", "1.0.0", 0},
		{"pre-release less than release", "1.0.0-beta.1", "1.0.0", -1},
		{"release greater than pre-release", "1.0.0", "1.0.0-beta.1", 1},
		{"pre-release vs pre-release", "1.0.0-beta.1", "1.0.0-beta.2", -1},
		{"equal pre-release", "1.0.0-beta.1", "1.0.0-beta.1", 0},
		{"pre-release with different base", "1.0.0-beta.1", "1.0.1-beta.1", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.v1, tt.v2)
			if got != tt.want {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     int
	}{
		{"critical", "critical", 4},
		{"Critical uppercase", "Critical", 4},
		{"CRITICAL all caps", "CRITICAL", 4},
		{"high", "high", 3},
		{"medium", "medium", 2},
		{"low", "low", 1},
		{"unknown", "unknown", 0},
		{"empty", "", 0},
		{"invalid", "invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityToLevel(tt.severity)
			if got != tt.want {
				t.Errorf("severityToLevel(%q) = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}

func TestCheckCondition(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		condition string
		want      bool
	}{
		{"less than true", "1.0.0", "< 2.0.0", true},
		{"less than false", "2.0.0", "< 2.0.0", false},
		{"less than or equal true", "2.0.0", "<= 2.0.0", true},
		{"greater than true", "3.0.0", "> 2.0.0", true},
		{"greater than false", "2.0.0", "> 2.0.0", false},
		{"greater than or equal true", "2.0.0", ">= 2.0.0", true},
		{"equal true", "2.0.0", "= 2.0.0", true},
		{"equal false", "2.0.1", "= 2.0.0", false},
		{"empty condition", "1.0.0", "", true},
		{"condition with spaces", "1.0.0", " < 2.0.0 ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCondition(tt.version, tt.condition)
			if got != tt.want {
				t.Errorf("checkCondition(%q, %q) = %v, want %v", tt.version, tt.condition, got, tt.want)
			}
		})
	}
}

func TestParseVersionParts(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    []int
	}{
		{"three parts", "1.2.3", []int{1, 2, 3}},
		{"two parts", "1.2", []int{1, 2}},
		{"one part", "1", []int{1}},
		{"zeros", "0.0.0", []int{0, 0, 0}},
		{"large numbers", "100.200.300", []int{100, 200, 300}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVersionParts(tt.version)
			if len(got) != len(tt.want) {
				t.Errorf("parseVersionParts(%q) = %v, want %v", tt.version, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseVersionParts(%q)[%d] = %d, want %d", tt.version, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSplitPreRelease(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		wantBase       string
		wantPreRelease string
	}{
		{"no pre-release", "1.0.0", "1.0.0", ""},
		{"with pre-release", "1.0.0-beta.1", "1.0.0", "beta.1"},
		{"with rc", "2.3.4-rc.1", "2.3.4", "rc.1"},
		{"with alpha", "1.0.0-alpha", "1.0.0", "alpha"},
		{"empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBase, gotPreRelease := splitPreRelease(tt.version)
			if gotBase != tt.wantBase {
				t.Errorf("splitPreRelease(%q) base = %q, want %q", tt.version, gotBase, tt.wantBase)
			}
			if gotPreRelease != tt.wantPreRelease {
				t.Errorf("splitPreRelease(%q) preRelease = %q, want %q", tt.version, gotPreRelease, tt.wantPreRelease)
			}
		})
	}
}

func TestFilterVulnerableVersions(t *testing.T) {
	rule := NewKnownVulnerableActionsRule()

	vulns := []*VulnerabilityInfo{
		{
			GHSAID:          "GHSA-1",
			VulnerableRange: "< 2.0.0",
		},
		{
			GHSAID:          "GHSA-2",
			VulnerableRange: ">= 3.0.0, < 3.5.0",
		},
	}

	tests := []struct {
		name    string
		version string
		wantLen int
	}{
		{"affected by first", "1.5.0", 1},
		{"affected by second", "3.2.0", 1},
		{"not affected", "2.5.0", 0},
		{"above all", "4.0.0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.filterVulnerableVersions(vulns, tt.version)
			if len(got) != tt.wantLen {
				t.Errorf("filterVulnerableVersions(vulns, %q) returned %d vulns, want %d", tt.version, len(got), tt.wantLen)
			}
		})
	}
}
