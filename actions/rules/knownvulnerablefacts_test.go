package rules

import (
	"context"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// knownVulnerableFacts are the answers of the facts the examples of
// known-vulnerable-actions ask, as the GitHub API gave them on 2026-10-15
// and, for the packages of the advisories added on 2026-11-07, on
// 2026-11-07, and for tmatens/compose-lint on 2026-11-13 (the SHAs and the
// advisories; example-org and the SHAs of repeated
// digits are made up, as the examples say). limitFacts answers from them.
var knownVulnerableFacts = func() map[facts.Kind]map[string]facts.RawAnswer {
	file := "{\"schema\":\"sisakulint/facts/v0\",\"facts\":[" + strings.Join([]string{
		`{"query":{"kind":"git.commit-tags","repo":"Azure/setup-kubectl","sha":"6025c840858f1afa584a5190a4426c338f59e503"},"state":"found","value":["refs/tags/v2.1"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"Azure/setup-kubectl","sha":"901a10e89ea615cf61f57ac05cecdf23e7de06d8"},"state":"found","value":["refs/tags/v3","refs/tags/v3.2"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"actions/download-artifact","sha":"87c55149d96e628cc2ef7e6fc2aab372015aec85"},"state":"found","value":["refs/tags/v4.1.3"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"actions/download-artifact","sha":"eaceaf801fd36c7dee90939fad912460b18a1ffe"},"state":"found","value":["refs/tags/v4.1.2"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"example-org/example-action","sha":"1111111111111111111111111111111111111111"},"state":"found","value":["refs/tags/v1.0.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"example-org/example-action","sha":"2222222222222222222222222222222222222222"},"state":"found","value":["refs/tags/v1.0.1"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"github/codeql-action","sha":"d68b2d4edb4189fd2a5366ac14e72027bd4b37dd"},"state":"found","value":["refs/tags/v3.28.2"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"lycheeverse/lychee-action","sha":"2bb232618be239862e31382c5c0eaeba12e5e966"},"state":"found","value":["refs/tags/v2.0.1"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"lycheeverse/lychee-action","sha":"7cd0af4c74a61395d455af97419279d86aafaede"},"state":"found","value":["refs/tags/v2.0.2"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tj-actions/branch-names","sha":"ab304d8562e2f137165e1d930e6d22d431189074"},"state":"found","value":["refs/tags/v7.0.6"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tj-actions/branch-names","sha":"e497ceb8ccd43fd9573cf2e375216625bc411d1f"},"state":"found","value":["refs/tags/v9.0.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tj-actions/changed-files","sha":"03334d095e2739fa9ac4034ec16f66d5d01e9eba"},"state":"found","value":["refs/tags/v44.5.1"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tj-actions/changed-files","sha":"1254cca6ac8b9c3047ba83a11b20c9dd8d9b0572"},"state":"found","value":[]}`,
		`{"query":{"kind":"git.ref-commit","repo":"tj-actions/changed-files","ref":"main"},"state":"found","value":{"ref":"refs/heads/main","sha":"1254cca6ac8b9c3047ba83a11b20c9dd8d9b0572"}}`,
		`{"query":{"kind":"git.ref-commit","repo":"example-org/example-action","ref":"v1.0.1"},"state":"found","value":{"ref":"refs/tags/v1.0.1","sha":"2222222222222222222222222222222222222222"}}`,
		`{"query":{"kind":"git.ref-commit","repo":"lycheeverse/lychee-action","ref":"v2.0.2"},"state":"found","value":{"ref":"refs/tags/v2.0.2","sha":"7cd0af4c74a61395d455af97419279d86aafaede"}}`,
		`{"query":{"kind":"git.ref-commit","repo":"Azure/setup-kubectl","ref":"v3"},"state":"found","value":{"ref":"refs/tags/v3","sha":"901a10e89ea615cf61f57ac05cecdf23e7de06d8"}}`,
		`{"query":{"kind":"git.ref-commit","repo":"github/codeql-action","ref":"v3.28.3"},"state":"found","value":{"ref":"refs/tags/v3.28.3","sha":"dd196fa9ce80b6bacc74ca1c32bd5b0ba22efca7"}}`,
		`{"query":{"kind":"git.ref-commit","repo":"actions/download-artifact","ref":"v4.1.3"},"state":"found","value":{"ref":"refs/tags/v4.1.3","sha":"87c55149d96e628cc2ef7e6fc2aab372015aec85"}}`,
		`{"query":{"kind":"git.ref-commit","repo":"tj-actions/changed-files","ref":"v46.0.1"},"state":"found","value":{"ref":"refs/tags/v46.0.1","sha":"2f7c5bfce28377bc069a65ba478de0a74aa0ca32"}}`,
		`{"query":{"kind":"git.ref-commit","repo":"tj-actions/branch-names","ref":"v9.0.0"},"state":"found","value":{"ref":"refs/tags/v9.0.0","sha":"e497ceb8ccd43fd9573cf2e375216625bc411d1f"}}`,
		`{"query":{"kind":"package.advisories","package":"Azure/setup-kubectl","version":"v2.1"},"state":"found","value":[{"ghsa_id":"GHSA-p756-rfxh-x63h","severity":"low","vulnerable_version_range":"< 3","first_patched_version":"3"}]}`,
		`{"query":{"kind":"package.advisories","package":"Azure/setup-kubectl","version":"v3.2"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"Azure/setup-kubectl"},"state":"found","value":[{"ghsa_id":"GHSA-p756-rfxh-x63h","severity":"low","vulnerable_version_range":"< 3","first_patched_version":"3"}]}`,
		`{"query":{"kind":"package.advisories","package":"actions/download-artifact","version":"v4.1.2"},"state":"found","value":[{"ghsa_id":"GHSA-cxww-7g56-2vh6","severity":"high","vulnerable_version_range":">= 4.0.0, < 4.1.3","first_patched_version":"4.1.3"}]}`,
		`{"query":{"kind":"package.advisories","package":"actions/download-artifact","version":"v4.1.3"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"actions/download-artifact"},"state":"found","value":[{"ghsa_id":"GHSA-cxww-7g56-2vh6","severity":"high","vulnerable_version_range":">= 4.0.0, < 4.1.3","first_patched_version":"4.1.3"}]}`,
		`{"query":{"kind":"package.advisories","package":"example-org/composite-action"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"example-org/example-action","version":"v1.0.0"},"state":"found","value":[{"ghsa_id":"GHSA-2222-3333-4444","severity":"unknown","vulnerable_version_range":"< 1.0.1","first_patched_version":"1.0.1"}]}`,
		`{"query":{"kind":"package.advisories","package":"example-org/example-action","version":"v1.0.1"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"example-org/example-action"},"state":"found","value":[{"ghsa_id":"GHSA-2222-3333-4444","severity":"unknown","vulnerable_version_range":"< 1.0.1","first_patched_version":"1.0.1"}]}`,
		`{"query":{"kind":"package.advisories","package":"example-org/unanswered-action"},"state":"unknown","reason":"the example does not answer it"}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action","version":"v3.28.2"},"state":"found","value":[{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","vulnerable_version_range":">= 3.26.11, <= 3.28.2","first_patched_version":"3.28.3"},{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","vulnerable_version_range":">= 2.26.11, < 3.0.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action"},"state":"found","value":[{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","vulnerable_version_range":">= 3.26.11, <= 3.28.2","first_patched_version":"3.28.3"},{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","vulnerable_version_range":">= 2.26.11, < 3.0.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/analyze","version":"v3.28.2"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/analyze"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/init","version":"v3.28.2"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/init"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/upload-sarif","version":"v3.28.2"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"github/codeql-action/upload-sarif"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"lycheeverse/lychee-action","version":"v2.0.1"},"state":"found","value":[{"ghsa_id":"GHSA-65rg-554r-9j5x","severity":"medium","vulnerable_version_range":"< 2.0.2","first_patched_version":"2.0.2"}]}`,
		`{"query":{"kind":"package.advisories","package":"lycheeverse/lychee-action","version":"v2.0.2"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"lycheeverse/lychee-action"},"state":"found","value":[{"ghsa_id":"GHSA-65rg-554r-9j5x","severity":"medium","vulnerable_version_range":"< 2.0.2","first_patched_version":"2.0.2"}]}`,
		`{"query":{"kind":"package.advisories","package":"pytorch/pytorch"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"pytorch/pytorch/.github/actions/filter-test-configs"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"tj-actions/branch-names","version":"v7.0.6"},"state":"found","value":[{"ghsa_id":"GHSA-gq52-6phf-x2r6","severity":"critical","vulnerable_version_range":"<= 8.2.1","first_patched_version":"9.0.0"},{"ghsa_id":"GHSA-8v8w-v8xg-79rf","severity":"critical","vulnerable_version_range":"< 7.0.7","first_patched_version":"7.0.7"}]}`,
		`{"query":{"kind":"package.advisories","package":"tj-actions/branch-names","version":"v9.0.0"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"tj-actions/branch-names"},"state":"found","value":[{"ghsa_id":"GHSA-gq52-6phf-x2r6","severity":"critical","vulnerable_version_range":"<= 8.2.1","first_patched_version":"9.0.0"},{"ghsa_id":"GHSA-8v8w-v8xg-79rf","severity":"critical","vulnerable_version_range":"< 7.0.7","first_patched_version":"7.0.7"}]}`,
		`{"query":{"kind":"package.advisories","package":"tj-actions/changed-files","version":"v44.5.1"},"state":"found","value":[{"ghsa_id":"GHSA-mrrh-fwg8-r2c3","severity":"high","vulnerable_version_range":"<= 45.0.7","first_patched_version":"46.0.1"}]}`,
		`{"query":{"kind":"package.advisories","package":"tj-actions/changed-files"},"state":"found","value":[{"ghsa_id":"GHSA-mrrh-fwg8-r2c3","severity":"high","vulnerable_version_range":"<= 45.0.7","first_patched_version":"46.0.1"},{"ghsa_id":"GHSA-mcph-m25j-8j63","severity":"high","vulnerable_version_range":"< 41","first_patched_version":"41"}]}`,
		`{"query":{"kind":"git.commit-tags","repo":"wktk/conflibot","sha":"4881912dc3fe459059127d667251d5b324622299"},"state":"found","value":["refs/tags/v1.2.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"wktk/conflibot","sha":"59e255c49c920fd6b67471ab9ef3bf194439a3f2"},"state":"found","value":["refs/tags/v1.2.1"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"wktk/conflibot","ref":"v1.2.1"},"state":"found","value":{"ref":"refs/tags/v1.2.1","sha":"59e255c49c920fd6b67471ab9ef3bf194439a3f2"}}`,
		`{"query":{"kind":"package.advisories","package":"wktk/conflibot","version":"v1.2.0"},"state":"found","value":[{"ghsa_id":"GHSA-2qvg-qr73-mqxp","severity":"critical","vulnerable_version_range":"< 1.2.1","first_patched_version":"1.2.1"}]}`,
		`{"query":{"kind":"package.advisories","package":"wktk/conflibot","version":"v1.2.1"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"wktk/conflibot"},"state":"found","value":[{"ghsa_id":"GHSA-2qvg-qr73-mqxp","severity":"critical","vulnerable_version_range":"< 1.2.1","first_patched_version":"1.2.1"}]}`,
		`{"query":{"kind":"git.commit-tags","repo":"BoldestDungeon/steam-workshop-deploy","sha":"a6e5b5fa5963fb5b9e22c7e0dfa046a1481c4974"},"state":"found","value":["refs/tags/v1.0.1"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"BoldestDungeon/steam-workshop-deploy","ref":"v2.0.0"},"state":"absent"}`,
		`{"query":{"kind":"package.advisories","package":"BoldestDungeon/steam-workshop-deploy","version":"v1.0.1"},"state":"found","value":[{"ghsa_id":"GHSA-x6gv-2rvh-qmp6","severity":"critical","vulnerable_version_range":"< 2.0.0","first_patched_version":"2.0.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"BoldestDungeon/steam-workshop-deploy"},"state":"found","value":[{"ghsa_id":"GHSA-x6gv-2rvh-qmp6","severity":"critical","vulnerable_version_range":"< 2.0.0","first_patched_version":"2.0.0"}]}`,
		`{"query":{"kind":"git.commit-tags","repo":"super-linter/super-linter","sha":"502f4fe48a81a392756e173e39a861f8c8efe056"},"state":"found","value":["refs/tags/v8.3.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"super-linter/super-linter","sha":"47984f49b4e87383eed97890fe2dca6063bbd9c3"},"state":"found","value":["refs/tags/v8.3.1"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"super-linter/super-linter","ref":"v8.3.1"},"state":"found","value":{"ref":"refs/tags/v8.3.1","sha":"47984f49b4e87383eed97890fe2dca6063bbd9c3"}}`,
		`{"query":{"kind":"package.advisories","package":"super-linter/super-linter","version":"v8.3.0"},"state":"found","value":[{"ghsa_id":"GHSA-r79c-pqj3-577x","severity":"high","vulnerable_version_range":">= 6.0.0, < 8.3.1","first_patched_version":"8.3.1"}]}`,
		`{"query":{"kind":"package.advisories","package":"super-linter/super-linter","version":"v8.3.1"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"super-linter/super-linter"},"state":"found","value":[{"ghsa_id":"GHSA-r79c-pqj3-577x","severity":"high","vulnerable_version_range":">= 6.0.0, < 8.3.1","first_patched_version":"8.3.1"}]}`,
		`{"query":{"kind":"git.commit-tags","repo":"SonarSource/sonarqube-scan-action","sha":"1a6d90ebcb0e6a6b1d87e37ba693fe453195ae25"},"state":"found","value":["refs/tags/v5.3.1"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"SonarSource/sonarqube-scan-action","sha":"fd88b7d7ccbaefd23d8f36f73b59db7a3d246602"},"state":"found","value":["refs/tags/v6","refs/tags/v6.0","refs/tags/v6.0.0"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"SonarSource/sonarqube-scan-action","ref":"v6.0.0"},"state":"found","value":{"ref":"refs/tags/v6.0.0","sha":"fd88b7d7ccbaefd23d8f36f73b59db7a3d246602"}}`,
		`{"query":{"kind":"package.advisories","package":"SonarSource/sonarqube-scan-action","version":"v5.3.1"},"state":"found","value":[{"ghsa_id":"GHSA-5xq9-5g24-4g6f","severity":"high","vulnerable_version_range":">= 4.0.0, < 6.0.0","first_patched_version":"6.0.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"SonarSource/sonarqube-scan-action","version":"v6.0.0"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"SonarSource/sonarqube-scan-action"},"state":"found","value":[{"ghsa_id":"GHSA-5xq9-5g24-4g6f","severity":"high","vulnerable_version_range":">= 4.0.0, < 6.0.0","first_patched_version":"6.0.0"},{"ghsa_id":"GHSA-f79p-9c5r-xg88","severity":"high","vulnerable_version_range":">= 4.0.0, <= 5.3.0","first_patched_version":"5.3.1"}]}`,
		`{"query":{"kind":"git.commit-tags","repo":"Tiryoh/actions-mkdocs","sha":"14d3fd544b7a2bcffcdd86b05d558f20c244c9fc"},"state":"found","value":["refs/tags/v0.24","refs/tags/v0.24.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"Tiryoh/actions-mkdocs","sha":"08208dbe49e1d15f9a58a6eb691e7dfb2df2253c"},"state":"found","value":["refs/tags/v0","refs/tags/v0.25","refs/tags/v0.25.0"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"Tiryoh/actions-mkdocs","ref":"v0.25.0"},"state":"found","value":{"ref":"refs/tags/v0.25.0","sha":"08208dbe49e1d15f9a58a6eb691e7dfb2df2253c"}}`,
		`{"query":{"kind":"package.advisories","package":"Tiryoh/actions-mkdocs","version":"v0.24.0"},"state":"found","value":[{"ghsa_id":"GHSA-6p2j-742g-835f","severity":"medium","vulnerable_version_range":"<= 0.24.0","first_patched_version":"0.25.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"Tiryoh/actions-mkdocs","version":"v0.25.0"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"Tiryoh/actions-mkdocs"},"state":"found","value":[{"ghsa_id":"GHSA-6p2j-742g-835f","severity":"medium","vulnerable_version_range":"<= 0.24.0","first_patched_version":"0.25.0"}]}`,
		`{"query":{"kind":"git.commit-tags","repo":"SonarSource/sonarqube-scan-action","sha":"713881670b6b3676cda39549040e2d88c70d582e"},"state":"found","value":["refs/tags/v8.2.0"]}`,
		`{"query":{"kind":"package.advisories","package":"SonarSource/sonarqube-scan-action","version":"v8.2.0"},"state":"found","value":[]}`,
		`{"query":{"kind":"git.commit-tags","repo":"SonarSource/sonarqube-scan-action","sha":"11bd71901bbe5b1630ceea73d27597364c9af683"},"state":"found","value":["refs/tags/v4"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"gradle/gradle-build-action","sha":"5056fa9d50478a14af3c9925c12ca02318659d3e"},"state":"found","value":["refs/tags/v2.4.1"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"gradle/gradle-build-action","sha":"749f47bda3e44aa060e82d7b3ef7e40d953bd629"},"state":"found","value":["refs/tags/v2.4.2"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"gradle/gradle-build-action","ref":"v2.4.2"},"state":"found","value":{"ref":"refs/tags/v2.4.2","sha":"749f47bda3e44aa060e82d7b3ef7e40d953bd629"}}`,
		`{"query":{"kind":"package.advisories","package":"gradle/gradle-build-action","version":"v2.4.1"},"state":"found","value":[{"ghsa_id":"GHSA-h3qr-39j9-4r5v","severity":"high","vulnerable_version_range":"< 2.4.2","first_patched_version":"2.4.2"}]}`,
		`{"query":{"kind":"package.advisories","package":"gradle/gradle-build-action","version":"v2.4.2"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"gradle/gradle-build-action"},"state":"found","value":[{"ghsa_id":"GHSA-h3qr-39j9-4r5v","severity":"high","vulnerable_version_range":"< 2.4.2","first_patched_version":"2.4.2"}]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tmatens/compose-lint","sha":"2d42617e4c6416f797bbfc6a057950131fa02df3"},"state":"found","value":["refs/tags/v0.32.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tmatens/compose-lint","sha":"691e08bd1881ada886e3f556d0793079e8114451"},"state":"found","value":["refs/tags/v0.33.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tmatens/compose-lint","sha":"a6a7a76736de1c72abfa96c41ff8af556ffdc55f"},"state":"found","value":["refs/tags/v0.31.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tmatens/compose-lint","sha":"adf00708734b772686337b69831c8e3912fa0ed4"},"state":"found","value":["refs/tags/v0.30.0"]}`,
		`{"query":{"kind":"git.commit-tags","repo":"tmatens/compose-lint","sha":"d6e1817352200adbd0a72893fd7ea7880874759b"},"state":"found","value":["refs/tags/v0.24.0"]}`,
		`{"query":{"kind":"git.ref-commit","repo":"tmatens/compose-lint","ref":"v0.33.0"},"state":"found","value":{"ref":"refs/tags/v0.33.0","sha":"691e08bd1881ada886e3f556d0793079e8114451"}}`,
		`{"query":{"kind":"package.advisories","package":"tmatens/compose-lint","version":"v0.24.0"},"state":"found","value":[{"ghsa_id":"GHSA-whr6-fgpq-fpv9","severity":"low","vulnerable_version_range":">= 0.2.0, <= 0.24.0","first_patched_version":"0.25.0"},{"ghsa_id":"GHSA-88f4-frh5-gmcr","severity":"low","vulnerable_version_range":">= 0.2.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-jf3h-8jvx-vcrg","severity":"low","vulnerable_version_range":">= 0.22.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-6f4g-xm8v-pgv6","severity":"medium","vulnerable_version_range":">= 0.2.0, <= 0.30.0","first_patched_version":"0.31.0"},{"ghsa_id":"GHSA-6wcv-rj3c-mhv3","severity":"low","vulnerable_version_range":">= 0.22.0, <= 0.30.0","first_patched_version":"0.31.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"tmatens/compose-lint","version":"v0.30.0"},"state":"found","value":[{"ghsa_id":"GHSA-xcf7-88g6-7xr8","severity":"low","vulnerable_version_range":">= 0.30.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-88f4-frh5-gmcr","severity":"low","vulnerable_version_range":">= 0.2.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-jf3h-8jvx-vcrg","severity":"low","vulnerable_version_range":">= 0.22.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-6f4g-xm8v-pgv6","severity":"medium","vulnerable_version_range":">= 0.2.0, <= 0.30.0","first_patched_version":"0.31.0"},{"ghsa_id":"GHSA-6wcv-rj3c-mhv3","severity":"low","vulnerable_version_range":">= 0.22.0, <= 0.30.0","first_patched_version":"0.31.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"tmatens/compose-lint","version":"v0.31.0"},"state":"found","value":[{"ghsa_id":"GHSA-xcf7-88g6-7xr8","severity":"low","vulnerable_version_range":">= 0.30.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-88f4-frh5-gmcr","severity":"low","vulnerable_version_range":">= 0.2.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-jf3h-8jvx-vcrg","severity":"low","vulnerable_version_range":">= 0.22.0, <= 0.31.0","first_patched_version":"0.32.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"tmatens/compose-lint","version":"v0.32.0"},"state":"found","value":[{"ghsa_id":"GHSA-rm8w-w798-g545","severity":"low","vulnerable_version_range":"= 0.32.0","first_patched_version":"0.33.0"}]}`,
		`{"query":{"kind":"package.advisories","package":"tmatens/compose-lint","version":"v0.33.0"},"state":"found","value":[]}`,
		`{"query":{"kind":"package.advisories","package":"tmatens/compose-lint"},"state":"found","value":[{"ghsa_id":"GHSA-xcf7-88g6-7xr8","severity":"low","vulnerable_version_range":">= 0.30.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-rm8w-w798-g545","severity":"low","vulnerable_version_range":"= 0.32.0","first_patched_version":"0.33.0"},{"ghsa_id":"GHSA-whr6-fgpq-fpv9","severity":"low","vulnerable_version_range":">= 0.2.0, <= 0.24.0","first_patched_version":"0.25.0"},{"ghsa_id":"GHSA-88f4-frh5-gmcr","severity":"low","vulnerable_version_range":">= 0.2.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-jf3h-8jvx-vcrg","severity":"low","vulnerable_version_range":">= 0.22.0, <= 0.31.0","first_patched_version":"0.32.0"},{"ghsa_id":"GHSA-6f4g-xm8v-pgv6","severity":"medium","vulnerable_version_range":">= 0.2.0, <= 0.30.0","first_patched_version":"0.31.0"},{"ghsa_id":"GHSA-6wcv-rj3c-mhv3","severity":"low","vulnerable_version_range":">= 0.22.0, <= 0.30.0","first_patched_version":"0.31.0"}]}`,
	}, ",") + "]}"
	s, err := facts.LoadStore([]byte(file))
	if err != nil {
		panic(err)
	}
	out := map[facts.Kind]map[string]facts.RawAnswer{}
	for _, e := range s.Entries() {
		k, _ := facts.EncodeQuery(e.Query)
		if out[e.Query.Kind()] == nil {
			out[e.Query.Kind()] = map[string]facts.RawAnswer{}
		}
		out[e.Query.Kind()][string(k)] = e.RawAnswer
	}
	return out
}()

// knownVulnerableAnswer is the answer of knownVulnerableFacts to q, or
// false when it has none. Of the kinds known-vulnerable-actions adds, a
// fact it has not is a package with no advisory, or a commit no tag
// points to.
func knownVulnerableAnswer(_ context.Context, q facts.Query) (facts.RawAnswer, bool) {
	k, err := facts.EncodeQuery(q)
	if err != nil {
		return facts.RawAnswer{}, false
	}
	if a, ok := knownVulnerableFacts[q.Kind()][string(k)]; ok {
		return a, true
	}
	switch q.(type) {
	case facts.PackageAdvisories, facts.GitCommitTags:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("[]")}, true
	}
	return facts.RawAnswer{}, false
}
