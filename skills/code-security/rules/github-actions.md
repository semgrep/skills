---
title: Secure GitHub Actions
impact: HIGH
impactDescription: Prevents code injection, secrets theft, and supply chain attacks in CI/CD pipelines
tags: security, github-actions, ci-cd, cwe-78, cwe-94, cwe-913
---

## Secure GitHub Actions

GitHub Actions workflows can be vulnerable to several security issues including script injection, secrets exposure, and supply chain attacks. Attackers who exploit these vulnerabilities can steal repository secrets, inject malicious code, or compromise the entire CI/CD pipeline.

### Key Security Risks

1. **Script Injection**: Using untrusted input (like PR titles or issue bodies) directly in `run:` commands allows attackers to inject arbitrary code
2. **Privileged Triggers**: `pull_request_target` and `workflow_run` events run with elevated privileges, making checkout of untrusted code dangerous
3. **Secrets Exposure**: Improper handling of secrets can leak them in logs or to malicious code
4. **Supply Chain**: Third-party actions not pinned to commit SHAs can be compromised

---

### Run Shell Injection (CWE-78)

Using variable interpolation `${{...}}` with `github` context data in a `run:` step could allow an attacker to inject their own code into the runner. This would allow them to steal secrets and code. `github` context data can have arbitrary user input and should be treated as untrusted.

**Incorrect (vulnerable to script injection via PR title):**
```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Check PR title
        # ruleid: run-shell-injection
        run: |
          title="${{ github.event.pull_request.title }}"
          if [[ $title =~ ^octocat ]]; then
          echo "PR title starts with 'octocat'"
          exit 0
          else
          echo "PR title did not start with 'octocat'"
          exit 1
          fi
```

**Incorrect (vulnerable to injection via workflow inputs):**
```yaml
on:
  workflow_dispatch:
    inputs:
      message_to_print:
        type: string
        required: false

jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Print a message
        # ruleid: run-shell-injection
        run: |
          echo "${{github.event.inputs.message_to_print}}"
```

**Incorrect (vulnerable to injection via issue title):**
```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Show issue title
        # ruleid: run-shell-injection
        run: |
          echo "${{ github.event.issue.title }}"
```

**Incorrect (vulnerable to injection via commit author email):**
```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Show author email
        # ruleid: run-shell-injection
        run: |
          echo "${{ github.event.commits.fix-bug.author.email }}"
```

**Correct (safe use of GitHub context):**
```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Push commit hash if PR
        if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
        # ok: run-shell-injection
        run: |
          tag=returntocorp/semgrep:${{ github.sha }}
          docker build -t "$tag" .
          docker push "$tag"
```

**Correct (using secrets safely):**
```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: benign
        # ok: run-shell-injection
        run: |
          AUTH_HEADER="Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}";
          HEADER="Accept: application/vnd.github.v3+json";
```

**Correct (using workflow_run artifacts_url safely):**
```yaml
jobs:
  docker-build:
    runs-on: ubuntu-latest
    steps:
      - name: Download and Extract Artifacts
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        # ok: run-shell-injection
        run: |
          mkdir -p artifacts && cd artifacts
          artifacts_url=${{ github.event.workflow_run.artifacts_url }}
          gh api "$artifacts_url" -q '.artifacts[] | [.name, .archive_download_url] | @tsv' | while read artifact
          do
            IFS=$'\t' read name url <<< "$artifact"
            gh api $url > "$name.zip"
            unzip -d "$name" "$name.zip"
          done
```

**Fix**: Use an intermediate environment variable with `env:` to store the data and use the environment variable in the `run:` script. Be sure to use double-quotes around the environment variable, like this: `"$ENVVAR"`.

Reference: [GitHub Actions Security Hardening - Script Injections](https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)

---

### GitHub Script Injection (CWE-94)

Using variable interpolation `${{...}}` with `github` context data in `actions/github-script`'s `script:` step could allow an attacker to inject their own code into the runner.

**Incorrect (vulnerable to injection via PR title in github-script):**
```yaml
jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Run script 1
        uses: actions/github-script@v6
        if: steps.report-diff.outputs.passed == 'true'
        with:
          # ruleid: github-script-injection
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('/tmp/file.txt', {encoding: 'utf8'});

            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '${{ github.event.pull_request.title }}' + body
            })

            return true;
```

**Incorrect (vulnerable to injection via issue title in github-script):**
```yaml
jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Run script 2
        uses: actions/github-script@latest
        with:
          # ruleid: github-script-injection
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('/tmp/${{ github.event.issue.title }}.txt', {encoding: 'utf8'});

            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Thanks for reporting!'
            })

            return true;
```

**Correct (non-github-script action is safe):**
```yaml
jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Ok script 1
        uses: not-github/custom-action@latest
        with:
          # ok: github-script-injection
          script: |
            return ${{ github.event.issue.title }};
```

**Correct (using safe github context like artifacts_url):**
```yaml
jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Ok script 2
        uses: actions/github-script@latest
        with:
          # ok: github-script-injection
          script: |
            console.log('${{ github.event.workflow_run.artifacts_url }}');

            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Thanks for reporting!'
            })

            return true;
```

Reference: [GitHub Actions Untrusted Input](https://securitylab.github.com/research/github-actions-untrusted-input/)

---

### Pull Request Target Code Checkout (CWE-913)

When using `pull_request_target`, the Action runs in the context of the target repository with access to all repository secrets. Checking out the incoming PR code while having access to secrets is dangerous because you may inadvertently execute arbitrary code from the incoming PR.

**Incorrect (checking out PR code with pull_request_target):**
```yaml
# cf. https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
# INSECURE. Provided as an example only.
on:
  pull_request_target:
  pull_request:

jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: pull-request-target-code-checkout
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - uses: actions/setup-node@v1
      - run: |
          npm install
          npm build

      - uses: completely/fakeaction@v2
        with:
          arg1: ${{ secrets.supersecret }}
```

**Incorrect (using merge ref with pull_request_target):**
```yaml
on:
  pull_request_target:
  pull_request:

jobs:
  # cf. https://github.com/justinsteven/advisories/blob/master/2021_github_actions_checkspelling_token_leak_via_advice_symlink.md
  spelling:
    name: Spell checking
    runs-on: ubuntu-latest
    steps:
      # ruleid: pull-request-target-code-checkout
      - name: checkout-merge
        if: contains(github.event_name, 'pull_request')
        uses: actions/checkout@v2
        with:
          ref: refs/pull/${{github.event.pull_request.number}}/merge
```

**Correct (no checkout of PR code):**
```yaml
on:
  pull_request_target:
  pull_request:

jobs:
  this-is-safe-because-no-checkout:
    name: Echo
    runs-on: ubuntu-latest
    steps:
      # ok: pull-request-target-code-checkout
      - name: echo
        run: |
          echo "Hello, world"
```

Reference: [GitHub Actions Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)

---

### Workflow Run Target Code Checkout (CWE-913)

Similar to `pull_request_target`, when using `workflow_run`, the Action runs in the context of the target repository with access to all repository secrets. Checking out incoming PR code with this trigger is dangerous.

**Incorrect (checking out PR code with workflow_run):**
```yaml
on:
  workflow_run:
    workflows: ["smth-else"]
    types:
    - completed
  pull_request:

jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: workflow-run-target-code-checkout
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.workflow_run.head.sha }}

      - uses: actions/setup-node@v1
      - run: |
          npm install
          npm build

      - uses: completely/fakeaction@v2
        with:
          arg1: ${{ secrets.supersecret }}
```

**Incorrect (using merge ref with workflow_run):**
```yaml
on:
  workflow_run:
    workflows: ["smth-else"]
    types:
    - completed
  pull_request:

jobs:
  spelling:
    name: Spell checking
    runs-on: ubuntu-latest
    steps:
      # ruleid: workflow-run-target-code-checkout
      - name: checkout-merge
        if: contains(github.event_name, 'pull_request')
        uses: actions/checkout@v2
        with:
          ref: refs/pull/${{github.event.workflow_run.number}}/merge
```

**Correct (no checkout of PR code):**
```yaml
on:
  workflow_run:
    workflows: ["smth-else"]
    types:
    - completed
  pull_request:

jobs:
  this-is-safe-because-no-checkout:
    name: Echo
    runs-on: ubuntu-latest
    steps:
      # ok: workflow-run-target-code-checkout
      - name: echo
        run: |
          echo "Hello, world"
```

Reference: [GitHub Privilege Escalation Vulnerability](https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability)

---

### Curl Eval (CWE-78)

Data is being eval'd from a `curl` command. An attacker with control of the server in the `curl` command could inject malicious code into the `eval`, resulting in a system compromise.

**Incorrect (eval'ing data from curl):**
```yaml
name: Build and deploy Semgrep scanner lambda

on:
  workflow_dispatch:
  push:
    branches: develop

jobs:
  docker-build:
    runs-on: ubuntu-latest
    env:
      workdir: lambdas/run-semgrep
    steps:
      - uses: actions/checkout@v2
      - name:
          blah
          # ruleid: curl-eval
        run: |
          CONTENTS=$(curl https://blah.com)
          eval $CONTENTS
```

**Correct (safe docker build without eval):**
```yaml
name: Build and deploy Semgrep scanner lambda

on:
  workflow_dispatch:
  push:
    branches: develop

jobs:
  docker-build:
    runs-on: ubuntu-latest
    env:
      workdir: lambdas/run-semgrep
    steps:
      - uses: actions/checkout@v2
      - name: Build Docker image
        working-directory:
          ${{ env.workdir }}/src
          # ok: curl-eval
        run: docker build -t semgrep-scanner:latest .
```

**Fix**: Avoid eval'ing untrusted data if you can. If you must do this, consider checking the SHA sum of the content returned by the server to verify its integrity.

Reference: [GitHub Actions Security Hardening - Script Injections](https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)

---

### Allowed Unsecure Commands (CWE-749)

The environment variable `ACTIONS_ALLOW_UNSECURE_COMMANDS` grants permissions to use the deprecated `set-env` and `add-path` commands, which have a vulnerability that could allow environment variable modification by attackers.

**Incorrect (enabling unsecure commands in step env):**
```yaml
on: pull_request

name: command-processing-test
jobs:
  dangerous-job:
    name: example
    runs-on: ubuntu-latest
    steps:
      - name: dont-do-this
        env:
          # ruleid: allowed-unsecure-commands
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        run: |
          echo "don't do this"
```

**Incorrect (enabling unsecure commands in job env):**
```yaml
on: pull_request

name: command-processing-test
jobs:
  another-dangerous-job:
    name: example2
    runs-on: ubuntu-latest
    env:
      # ruleid: allowed-unsecure-commands
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      - name: or-this
        run: |
          echo "seriously, dont"
```

**Correct (no unsecure commands):**
```yaml
on: pull_request

name: command-processing-test
jobs:
  this-is-ok:
    name: example3
    runs-on: ubuntu-latest
    env: PREFIX = "~~^_^~~"
    run: |
      echo "$PREFIX hello"
```

**Fix**: Don't use `ACTIONS_ALLOW_UNSECURE_COMMANDS`. Instead, use Environment Files.

Reference: [GitHub Actions Environment Files](https://github.com/actions/toolkit/blob/main/docs/commands.md#environment-files)

---

### Third-Party Action Not Pinned to Commit SHA (CWE-1357, CWE-353)

An action sourced from a third-party repository on GitHub is not pinned to a full length commit SHA. Pinning an action to a full length commit SHA is currently the only way to use an action as an immutable release. This helps mitigate the risk of a bad actor adding a backdoor to the action's repository.

**Incorrect (using tag or branch reference):**
```yaml
on:
  pull_request_target:
  pull_request:

jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: fakerepo/comment-on-pr@v1
        with:
          message: |
            Thank you!

      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: fakerepo/comment-on-pr
        with:
          message: |
            Thank you!
```

**Incorrect (using short SHA):**
```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: completely/fakeaction@5fd3084
        with:
          arg2: ${{ secrets.supersecret2 }}
```

**Incorrect (unpinned Docker action):**
```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: docker://gcr.io/cloud-builders/gradle

      # ruleid: third-party-action-not-pinned-to-commit-sha
      - uses: docker://alpine:3.8
```

**Correct (pinned to full commit SHA):**
```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: completely/fakeaction@5fd3084fc36e372ff1fff382a39b10d03659f355
        with:
          arg2: ${{ secrets.supersecret2 }}
```

**Correct (Docker action with pinned digest):**
```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: docker://alpine@sha256:402d21757a03a114d273bbe372fa4b9eca567e8b6c332fa7ebf982b902207242
```

**Correct (GitHub-owned actions don't need pinning):**
```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: actions/checkout@v2
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: actions/setup-node@master

      # ok: third-party-action-not-pinned-to-commit-sha
      - name: Upload SARIF file for GitHub Advanced Security Dashboard
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif
        if: always()
```

**Correct (local actions don't need pinning):**
```yaml
jobs:
  build:
    name: Build and test
    runs-on: ubuntu-latest
    steps:
      # ok: third-party-action-not-pinned-to-commit-sha
      - uses: ./.github/actions/do-a-local-action
        with:
          arg1: ${{ secrets.supersecret1 }}

  build2:
    name: Build and test using a local workflow
    # ok: third-party-action-not-pinned-to-commit-sha
    uses: ./.github/workflows/use_a_local_workflow.yml@master
    secrets: inherit
    with:
      examplearg: true
```

Reference: [GitHub Actions Security Hardening - Using Third-Party Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)

---

### Unsafe Add-Mask Workflow Command (CWE-200)

GitHub Actions provides the `add-mask` workflow command to mask sensitive data in workflow logs. However, if workflow commands have been stopped (via `echo "::stop-commands::$stopMarker"`), sensitive data can be leaked. An attacker could copy the workflow to another branch and add a payload to stop workflow command processing, exposing secrets.

**Incorrect (using add-mask which can be bypassed):**
```yaml
name: Test Workflow

on:
  push:
    branches:
      - main

jobs:
  test-job:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'

      - name: Run script to generate token
        run: |
          TOKEN=$(openssl rand -hex 16)
          # ruleid: unsafe-add-mask-workflow-command
          echo "::add-mask::$TOKEN"
          echo "TOKEN=$TOKEN" >> $GITHUB_ENV

      - name: Use the token
        run: |
          echo "Using the token in the next step"
          curl -H "Authorization: Bearer $TOKEN" https://api.example.com

      - name: Print GitHub context
        run: |
          echo "GitHub context:"
          echo "${{ toJSON(github) }}"
          # ruleid: unsafe-add-mask-workflow-command
          echo "::add-mask::${{ secrets.GITHUB_TOKEN }}"
```

**Fix**: Prefer using GitHub's native secrets handling rather than relying on `add-mask` for security-critical masking. Consider the risk that an attacker with write access could modify the workflow to bypass masking.

Reference: [GitHub Actions Workflow Commands - Masking](https://github.com/github/docs/blob/main/content/actions/using-workflows/workflow-commands-for-github-actions.md#masking-a-value-in-a-log)

---

**References:**
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-749: Exposed Dangerous Method or Function
- CWE-913: Improper Control of Dynamically-Managed Code Resources
- CWE-1357: Reliance on Insufficiently Trustworthy Component
- CWE-353: Missing Support for Integrity Check
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/learn-github-actions/security-hardening-for-github-actions)
- [GitHub Security Lab - Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [GitHub Security Lab - Untrusted Input](https://securitylab.github.com/research/github-actions-untrusted-input/)
- [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
