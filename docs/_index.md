+++
title = 'sisakulint Document'
date = 2024-10-06T02:14:29+09:00
draft = false
+++

# sisakulint Document

Before moving on, please consider giving us a GitHub star ⭐️. Thank you!

{{< popup_link2 href=https://github.com/ultra-supara/sisakulint >}}

{{< figure src="https://github.com/ultra-supara/homebrew-sisakulint/assets/67861004/e9801cbb-fbe1-4822-a5cd-d1daac33e90f" alt="sisakulint logo" width="300px" >}}

## Achievements

- It has been adopted by [CODEBLUE 2024](https://codeblue.jp/) , The Largest Security Conferences in Japan. ref :  [cybertamago](https://cybertamago.org/tools.php#sisakulint)

- It has been adopted by [Black Hat Asia 2025](https://www.blackhat.com/asia-25/arsenal-overview.html) , The World's Premier Technical Security Conference in Singapore.ref :  [Arsenal](https://www.blackhat.com/asia-25/arsenal/schedule/#sisakulint---ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions-43229)

## what is this?
In recent years, attacks targeting the Web Application Platform have been increasing rapidly.
sisakulint is **a static and fast SAST for GitHub Actions**. 
This great tool can automatically validate yaml files according to the guidelines in the security-related documentation provided by GitHub!
It also includes functionality as a static analysis tool that can check the policies of the guidelines that should be set for use in each organization.
These checks also comply with [the Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) provided by OWASP.
It implements most of the functions that can automatically check whether a workflow that meets the [security features](https://docs.github.com/ja/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) supported by github has been built to reduce the risk of malicious code being injected into the CI/CD pipeline or credentials such as tokens being stolen.
It does not support inspections that cannot be expressed in YAML and "repository level settings" that can be set by GitHub organization administrators.
It is intended to be used mainly by software developers and security personnel at user companies who work in blue teams. 
It is easy to introduce because it can be installed from brew.
It also implements an autofix function for errors related to security features as a lint.
It supports the SARIF format, which is the output format for static analysis. This allows [reviewdog](https://github.com/reviewdog/reviewdog?tab=readme-ov-file#sarif-format) to provide a rich UI for error triage on GitHub.

## Rules by Severity

sisakulint categorizes security rules by severity based on CVSS scores, attack impact, and exploitability.

### Severity Summary

| Severity | Count | CVSS Range | Description |
|----------|-------|------------|-------------|
| **Critical** | 14 | 9.0-10.0 | Immediate risk, can lead to RCE or full compromise |
| **High** | 17 | 7.0-8.9 | Significant risk, enables serious attacks |
| **Medium** | 13 | 4.0-6.9 | Moderate risk, requires specific conditions |
| **Low** | 5 | 0.1-3.9 | Best practices, minimal direct security impact |

### Critical Severity Rules (9.0-10.0)

| Rule | CVSS | Description | Auto-fix |
|------|------|-------------|----------|
| [code-injection-critical]({{< ref "codeinjectioncritical.md" >}}) | 10/10 | Code injection in privileged triggers (pull_request_target, workflow_run, issue_comment) | Yes |
| [env-var-injection-critical]({{< ref "envvarinjectioncritical.md" >}}) | 9/10 | Environment variable injection via $GITHUB_ENV in privileged triggers | Yes |
| [env-path-injection-critical]({{< ref "envpathinjectioncritical.md" >}}) | 9/10 | PATH injection via $GITHUB_PATH in privileged triggers | Yes |
| [artifact-poisoning-critical]({{< ref "artifactpoisoningcritical.md" >}}) | 9/10 | Artifact download without validation in privileged triggers | Yes |
| [untrusted-checkout]({{< ref "untrustedcheckout.md" >}}) | 9.3 | Checkout of untrusted PR code in privileged contexts | Yes |
| [untrusted-checkout-toctou-critical]({{< ref "untrustedcheckouttoctouhigh.md" >}}) | 9.3 | TOCTOU vulnerability with labeled event type and mutable refs | Yes |
| [impostor-commit]({{< ref "impostorcommit.md" >}}) | 9.8 | Detects impostor commits from fork network (supply chain attack) | Yes |
| [output-clobbering-critical]({{< ref "outputclobbering.md" >}}) | Critical | Output clobbering via $GITHUB_OUTPUT in privileged triggers | Yes |
| [argument-injection-critical]({{< ref "argumentinjection.md" >}}) | Critical | Command-line argument injection in privileged triggers | Yes |
| [request-forgery-critical]({{< ref "requestforgery.md" >}}) | Critical | SSRF vulnerabilities in privileged triggers | Yes |
| [dangerous-triggers-critical]({{< ref "dangeroustriggersrulecritical.md" >}}) | Critical | Privileged triggers without security mitigations | No |
| [reusable-workflow-taint]({{< ref "reusableworkflowtaint.md" >}}) | Critical | Untrusted input passed to reusable workflows (privileged triggers) | Yes |
| [secret-exfiltration]({{< ref "secretexfiltration.md" >}}) | Critical | Secret exfiltration via network commands | No |
| [artipacked]({{< ref "artipacked.md" >}}) | Critical | Credential leakage when checkout credentials are persisted and workspace is uploaded | Yes |

### High Severity Rules (7.0-8.9)

| Rule | CVSS | Description | Auto-fix |
|------|------|-------------|----------|
| [permissions]({{< ref "permissions.md" >}}) | 7/10 | Validates least-privilege permissions configuration | Yes |
| [deprecated-commands]({{< ref "deprecatedcommandsrule.md" >}}) | 7/10 | Detects deprecated workflow commands | No |
| [commit-sha]({{< ref "commitsharule.md" >}}) | 7/10 | Enforces commit SHA pinning for actions (supply chain protection) | Yes |
| [cache-poisoning]({{< ref "cachepoisoningrule.md" >}}) | 8/10 | Detects cache poisoning vulnerabilities | Yes |
| [secret-exposure]({{< ref "secretexposure.md" >}}) | 8/10 | Detects excessive secrets exposure via toJSON(secrets) or dynamic access | Yes |
| [bot-conditions]({{< ref "botconditions.md" >}}) | 8/10 | Detects spoofable bot detection conditions | Yes |
| [ref-confusion]({{< ref "refconfusion.md" >}}) | 8/10 | Detects ref confusion attacks (branch/tag name collision) | Yes |
| [obfuscation]({{< ref "obfuscation.md" >}}) | 7/10 | Detects obfuscated workflow patterns | Yes |
| [self-hosted-runners]({{< ref "selfhostedrunners.md" >}}) | 8/10 | Detects self-hosted runner usage in public repos | No |
| [untrusted-checkout-toctou-high]({{< ref "untrustedcheckouttoctouhigh.md" >}}) | 7.5 | TOCTOU vulnerability with deployment environment and mutable refs | Yes |
| [secrets-in-artifacts]({{< ref "secretsinartifacts.md" >}}) | 7.5/10 | Detects sensitive information in artifact uploads | Yes |
| [secrets-inherit]({{< ref "secretsinherit.md" >}}) | High | Detects excessive secret inheritance (secrets: inherit) | Yes |
| [cache-poisoning-poisonable-step]({{< ref "cachepoisoningrule.md" >}}) | High | Cache poisoning via execution of untrusted code after unsafe checkout | Yes |
| [unmasked-secret-exposure]({{< ref "unmaskedsecretexposure.md" >}}) | High | Detects unmasked secrets derived from fromJson() | Yes |
| [improper-access-control]({{< ref "improperaccesscontrol.md" >}}) | High | Detects improper access control with label-based approval | Yes |
| [known-vulnerable-actions]({{< ref "knownvulnerableactions.md" >}}) | Varies | Detects actions with known CVEs (inherits advisory severity) | Yes |
| [credentials]({{< ref "credentialsrule.md" >}}) | High | Detects hardcoded credentials | Yes |

### Medium Severity Rules (4.0-6.9)

| Rule | CVSS | Description | Auto-fix |
|------|------|-------------|----------|
| [code-injection-medium]({{< ref "codeinjectionmedium.md" >}}) | 6/10 | Code injection in normal triggers (pull_request, push) | Yes |
| [env-var-injection-medium]({{< ref "envvarinjectionmedium.md" >}}) | 5/10 | Environment variable injection in normal triggers | Yes |
| [env-path-injection-medium]({{< ref "envpathinjectionmedium.md" >}}) | 6/10 | PATH injection in normal triggers | Yes |
| [artifact-poisoning-medium]({{< ref "artifactpoisoningmedium.md" >}}) | 6/10 | Third-party artifact download in untrusted triggers | Yes |
| [expression]({{< ref "expression.md" >}}) | 5/10 | Validates GitHub Actions expression syntax | No |
| [conditional]({{< ref "conditionalrule.md" >}}) | 5/10 | Validates conditional expressions | Yes |
| [output-clobbering-medium]({{< ref "outputclobbering.md" >}}) | Medium | Output clobbering in normal triggers | Yes |
| [dangerous-triggers-medium]({{< ref "dangeroustriggersrulemedium.md" >}}) | Medium | Privileged triggers with partial mitigations | No |
| [argument-injection-medium]({{< ref "argumentinjection.md" >}}) | Medium | Command-line argument injection in normal triggers | Yes |
| [request-forgery-medium]({{< ref "requestforgery.md" >}}) | Medium | SSRF vulnerabilities in normal triggers | Yes |
| [unsound-contains]({{< ref "unsoundcontains.md" >}}) | 6/10 | Detects bypassable contains() function usage | Yes |
| [archived-uses]({{< ref "archiveduses.md" >}}) | 5/10 | Detects usage of archived actions | No |
| [unpinned-images]({{< ref "unpinnedimages.md" >}}) | 6/10 | Container images not pinned by SHA256 digest | No |

### Low Severity Rules (0.1-3.9)

| Rule | CVSS | Description | Auto-fix |
|------|------|-------------|----------|
| [timeout-minutes]({{< ref "timeoutminutesrule.md" >}}) | 3/10 | Enforces timeout-minutes configuration | Yes |
| [id]({{< ref "idrule.md" >}}) | 2/10 | Validates job and step ID naming conventions | No |
| [env-var]({{< ref "envvarrule.md" >}}) | 2/10 | Validates environment variable naming | No |
| [cache-bloat]({{< ref "cachebloatrule.md" >}}) | 3/10 | Detects cache bloat with restore/save pairs | Yes |
| [action-list]({{< ref "actionlist.md" >}}) | 3/10 | Policy enforcement for allowed/blocked actions | No |

## Main Tool features:
- **id collision detection**
 	- Environment variable names collision
 	- docs : https://sisaku-security.github.io/lint/docs/idrule/
 	- github ref https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#using-a-specific-shell

- **Hardcoded credentials detection by rego query language**
 	- docs : https://sisaku-security.github.io/lint/docs/credentialsrule/

- **commit-sha rule**
 	- docs : https://sisaku-security.github.io/lint/docs/commitsharule/
 	- github ref https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions

- **premissions rule**
 	- docs : https://sisaku-security.github.io/lint/docs/permissions/
 	- github ref : https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#permissions

- **workflow call rule**
  - docs : https://sisaku-security.github.io/lint/docs/workflowcall/
  - github ref : https://docs.github.com/en/actions/sharing-automations/reusing-workflows

- **timeout-minutes-rule**
  - docs : https://sisaku-security.github.io/lint/docs/timeoutminutesrule/
  - github ref : https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes
  - github ref : https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes

## install for macOS user

```bash
$ brew tap ultra-supara/homebrew-sisakulint
$ brew install sisakulint
```

## install from release page for Linux user

visit release page of this repository and download for yours.
https://github.com/ultra-supara/sisakulint/releases

```bash
$ cd < dir >
$ mv ./sisakulint /usr/local/bin/sisakulint
```

## Structure

![image](https://github.com/user-attachments/assets/4c6fa378-5878-48af-b95f-8b987b3cf7ef)

It automatically searches for YAML files in the .github/workflows directory, and the parser traverses the token column of the AST to check many rules. We've made it easy to triage by outputting clear results using a custom error formatter we made and [reviewdog](https://github.com/reviewdog/reviewdog) on the GitHub UI in SARIF format.

![image](https://github.com/user-attachments/assets/89604d2b-57f0-4ea2-9073-02ea9e422001)

[example url](https://github.com/ultra-supara/sisakulint/pull/138)

## Usage test
Create a file called test.yaml in the `.github/workflows` directory or go to your repository where your workflows file is located.
```yaml
name: Upload Release Archive

on:
  push:
    tags:
      - "v[0-9]+\\.[0-9]+\\.[0-9]+"

jobs:
  build:
    name: Upload Release Asset
    runs-on: macos-latest
    env:
          SIIISA=AAKUUU: foo
    steps:
      - name: Set version
        id: version
        run: |
          REPOSITORY=$(echo ${{ github.repository }} | sed -e "s#.*/##")
          echo ::set-output name=filename::$REPOSITORY-$VERSION
      - name: Checkout code
        uses: actions/checkout@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          submodules: true
      - name: Archive
        run: |
          zip -r ${{ steps.version.outputs.filename }}.zip ./ -x "*.git*"
      - run: echo 'Commit is pushed'
        # ERROR: It is always evaluated to true
        if: |
          ${{ github.event_name == 'push' }}
      - name: Create Release
        id: create_release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          FOO=BAR: foo
          FOO BAR: foo
        with:
          tag_name: ${{ github.ref }}
          release_name: Release ${{ github.ref }}
          draft: false
          prerelease: false
      - name: Upload Release Asset
        id: upload-release-asset
        uses: actions/upload-release-asset@v1
        with:
          upload_url: ${{ steps.create_release.outputs.upload_url }}
          asset_path: ./${{ steps.version.outputs.filename }}.zip
          asset_name: ${{ steps.version.outputs.filename }}.zip
          asset_content_type: application/zip

  test:
    runs-on: ubuntu-latest
    permissions:
      # ERROR: "checks" is correct scope name
      check: write
      # ERROR: Available values are "read", "write" or "none"
      issues: readable
    steps:
      - run: echo '${{ "hello" }}'
      - run: echo "${{ toJson(hashFiles('**/lock', '**/cache/') }}"
      - run: echo '${{ github.event. }}'

  run shell:
    steps:
      - run: echo 'hello'
```
execute following commands
```bash
$ sisakulint -h
$ sisakulint -debug
```
you will likely receive the following result...
```bash
[sisaku:🤔] linting repository... .
[sisaku:🤔] Detected project: /Users/para/go/src/github.com/ultra-supara/go_rego
[sisaku:🤔] the number of corrected yaml file 1 yaml files
[sisaku:🤔] validating workflow... .github/workflows/a.yaml
[sisaku:🤔] Detected project: /Users/para/go/src/github.com/ultra-supara/go_rego
[linter mode] no configuration file
[sisaku:🤔] parsed workflow in 2 0 ms .github/workflows/a.yaml
[SyntaxTreeVisitor] VisitStep was tooking line:61,col:9 steps, at step "2024-03-10 15:51:10.192583 +0900 JST m=+0.006376196" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:62,col:9 steps, at step "2024-03-10 15:51:10.192746 +0900 JST m=+0.006539807" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:63,col:9 steps, at step "2024-03-10 15:51:10.19276 +0900 JST m=+0.006553743" took 0 ms
[SyntaxTreeVisitor] VisitJobPost was tooking 3 jobs, at job "test" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking 3 steps took 0 ms
[SyntaxTreeVisitor] VisitJobPre took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:67,col:9 steps, at step "2024-03-10 15:51:10.192781 +0900 JST m=+0.006574644" took 0 ms
[SyntaxTreeVisitor] VisitJobPost was tooking 1 jobs, at job "run shell" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking 1 steps took 0 ms
[SyntaxTreeVisitor] VisitJobPre took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:15,col:9 steps, at step "2024-03-10 15:51:10.192799 +0900 JST m=+0.006592356" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:20,col:9 steps, at step "2024-03-10 15:51:10.192825 +0900 JST m=+0.006618901" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:25,col:9 steps, at step "2024-03-10 15:51:10.192845 +0900 JST m=+0.006638101" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:28,col:9 steps, at step "2024-03-10 15:51:10.192854 +0900 JST m=+0.006647451" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:32,col:9 steps, at step "2024-03-10 15:51:10.192865 +0900 JST m=+0.006658325" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking line:44,col:9 steps, at step "2024-03-10 15:51:10.192878 +0900 JST m=+0.006671659" took 0 ms
[SyntaxTreeVisitor] VisitJobPost was tooking 6 jobs, at job "build" took 0 ms
[SyntaxTreeVisitor] VisitStep was tooking 6 steps took 0 ms
[SyntaxTreeVisitor] VisitJobPre took 0 ms
[SyntaxTreeVisitor] VisitWorkflowPost took 0 ms
[SyntaxTreeVisitor] VisitJob was tooking 3 jobs took 0 ms
[SyntaxTreeVisitor] VisitWorkflowPre took 0 ms
[linter mode] env-var found 1 errors
[linter mode] id found 1 errors
[linter mode] permissions found 2 errors
[linter mode] workflow-call found 0 errors
[linter mode] expression found 3 errors
[linter mode] deprecated-commands found 1 errors
[linter mode] cond found 1 errors
[linter mode] missing-timeout-minutes found 3 errors
[linter mode] issue-injection found 5 errors
[sisaku:🤔] Found total 19 errors found in 0 found in ms .github/workflows/a.yaml
.github/workflows/a.yaml:9:3: timeout-minutes is not set for job build; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
      9 👈|  build:
        
.github/workflows/a.yaml:13:11: Environment variable name '"SIIISA=AAKUUU"' is not formatted correctly. Please ensure that it does not include characters such as '&', '=', or spaces, as these are not allowed in variable names. [env-var]
       13 👈|          SIIISA=AAKUUU: foo
                 
.github/workflows/a.yaml:17:14: workflow command "set-output" was deprecated. You should use `echo "{name}={value}" >> $GITHUB_OUTPUT` reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions [deprecated-commands]
       17 👈|        run: |
                    
.github/workflows/a.yaml:18:14: Direct use of ${{ ... }} in run steps; Use env instead. see also https://docs.github.com/ja/enterprise-cloud@latest/actions/security-guides/security-hardening-for-github-actions#example-of-a-script-injection-attack [issue-injection]
       18 👈|          REPOSITORY=$(echo ${{ github.repository }} | sed -e "s#.*/##")
                    
.github/workflows/a.yaml:27:14: Direct use of ${{ ... }} in run steps; Use env instead. see also https://docs.github.com/ja/enterprise-cloud@latest/actions/security-guides/security-hardening-for-github-actions#example-of-a-script-injection-attack [issue-injection]
       27 👈|          zip -r ${{ steps.version.outputs.filename }}.zip ./ -x "*.git*"
                    
.github/workflows/a.yaml:30:13: The condition '${{ github.event_name == 'push' }}
' will always evaluate to true. If you intended to use a literal value, please use ${{ true }}. Ensure there are no extra characters within the ${{ }} brackets in conditions. [cond]
       30 👈|        if: |
                   
.github/workflows/a.yaml:35:9: unexpected key "env" for "element of \"steps\" sequence" section. expected one of  [syntax]
       35 👈|        env:
               
.github/workflows/a.yaml:53:3: timeout-minutes is not set for job test; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
       53 👈|  test:
         
.github/workflows/a.yaml:57:7: unknown permission scope "check". all available permission scopes are "actions", "checks", "contents", "deployments", "discussions", "id-token", "issues", "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses" [permissions]
       57 👈|      check: write
             
.github/workflows/a.yaml:59:15: The value "readable" is not a valid permission for the scope "issues". Only 'read', 'write', or 'none' are acceptable values. [permissions]
       59 👈|      issues: readable
                     
.github/workflows/a.yaml:61:14: Direct use of ${{ ... }} in run steps; Use env instead. see also https://docs.github.com/ja/enterprise-cloud@latest/actions/security-guides/security-hardening-for-github-actions#example-of-a-script-injection-attack [issue-injection]
       61 👈|      - run: echo '${{ "hello" }}'
                    
.github/workflows/a.yaml:61:24: got unexpected char '"' while lexing expression, expecting 'a'..'z', 'A'..'Z', '_', '0'..'9', '', '}', '(', ')', '[', ']', '.', '!', '<', '>', '=', '&', '|', '*', ',', ' '. do you mean string literals? only single quotes are available for string delimiter [expression]
       61 👈|      - run: echo '${{ "hello" }}'
                              
.github/workflows/a.yaml:62:14: Direct use of ${{ ... }} in run steps; Use env instead. see also https://docs.github.com/ja/enterprise-cloud@latest/actions/security-guides/security-hardening-for-github-actions#example-of-a-script-injection-attack [issue-injection]
       62 👈|      - run: echo "${{ toJson(hashFiles('**/lock', '**/cache/') }}"
                    
.github/workflows/a.yaml:62:65: unexpected end of expression, while parsing arguments of function call, expected ",", ")" [expression]
       62 👈|      - run: echo "${{ toJson(hashFiles('**/lock', '**/cache/') }}"
                                                                       
.github/workflows/a.yaml:63:14: Direct use of ${{ ... }} in run steps; Use env instead. see also https://docs.github.com/ja/enterprise-cloud@latest/actions/security-guides/security-hardening-for-github-actions#example-of-a-script-injection-attack [issue-injection]
       63 👈|      - run: echo '${{ github.event. }}'
                    
.github/workflows/a.yaml:63:38: unexpected end of expression, while parsing expected an object property dereference (like 'a.b') or an array element dereference (like 'a.*'), expected "IDENT", "*" [expression]
       63 👈|      - run: echo '${{ github.event. }}'
                                            
.github/workflows/a.yaml:65:3: "runs-on" section is missing in job "run shell" [syntax]
       65 👈|  run shell:
         
.github/workflows/a.yaml:65:3: Invalid job ID "run shell". job IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
       65 👈|  run shell:
         
.github/workflows/a.yaml:65:3: timeout-minutes is not set for job run shell; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
       65 👈|  run shell:
```

1. Missing Timeout Minutes for Jobs

- Error: `timeout-minutes is not set for job build; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details.`

- Scenario: If a job runs indefinitely due to an unexpected error (e.g., a script hangs), it can consume resources unnecessarily, leading to increased costs and potential service disruptions. For example, if the `build` job is stuck, subsequent jobs that depend on its completion will also be delayed, causing the entire CI/CD pipeline to stall.

2. Incorrectly Formatted Environment Variable

- Error: `Environment variable name '"SIIISA=AAKUUU"' is not formatted correctly.`

- Scenario: If environment variables are not formatted correctly, the job may fail to execute as intended. For instance, if the variable is meant to be used in a command but is incorrectly defined, it could lead to runtime errors or unexpected behavior, such as failing to authenticate with an external service.

3. Deprecated Command Usage

- Error: `workflow command "set-output" was deprecated.`

- Scenario: Using deprecated commands can lead to future compatibility issues. If GitHub Actions removes support for the `set-output` command, workflows relying on it will break, causing failures in automated processes. This could delay releases or lead to incomplete deployments.

4. Direct Use of `${{ ... }}` in Run Steps

- Error: `Direct use of ${{ ... }} in run steps; Use env instead.`

- Scenario: Directly using expressions in run steps can expose the workflow to script injection attacks. For example, if an attacker can manipulate the input to the workflow, they could inject malicious commands that execute during the job, potentially compromising the repository or the CI/CD environment.

5. Always True Condition

- Error: `The condition '${{ github.event_name == 'push' }}' will always evaluate to true.`

- Scenario: If conditions are not set correctly, it can lead to unintended behavior in the workflow. For instance, if the intention was to run a step only for specific events, but the condition is always true, it could result in unnecessary steps being executed, wasting resources and time.

6. Invalid Permission Scopes

- Error: `unknown permission scope "check".`

- Scenario: Using invalid permission scopes can lead to failures in accessing necessary resources. For example, if the `test` job requires write access to checks but is incorrectly defined, it may not be able to create or update checks, leading to incomplete test results and a lack of visibility into the CI/CD process.

7. Invalid Job ID

- Error: `Invalid job ID "run shell". job IDs must start with a letter or '_'.`

- Scenario: If job IDs are not valid, the workflow will fail to execute. For example, if the job `run shell` is intended to run a shell command but is not recognized due to an invalid ID, it will not run at all, potentially skipping important steps in the workflow.

8. Missing Timeout Minutes for Additional Jobs

- Error  `timeout-minutes is not set for job test; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details.`

- Scenario: Similar to the first issue, if the `test` job runs indefinitely, it can block the workflow and lead to resource exhaustion. This can delay the entire CI/CD process, affecting deployment timelines and potentially leading to missed deadlines.

## Autofix 
- :todo:


## JSON schema for GitHub Actions syntax
paste yours `settings.json`

```
 "yaml.schemas": {
     "https://ultra-supara/homebrew-sisakulint/settings.json": "/.github/workflows/*.{yml,yaml}"
 }
```

## Links

- slides
- [poster](https://sechack365.nict.go.jp/achievement/2023/pdf/14C.pdf)
- video
