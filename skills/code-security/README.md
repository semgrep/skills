# Code Security Skill

Comprehensive security guidelines for writing secure code across 15+ languages, covering OWASP Top 10, infrastructure security, and coding best practices.

## Categories (28 Total)

### Critical Impact
- SQL Injection, Command Injection, XSS, XXE, Path Traversal
- Insecure Deserialization, Code Injection, Hardcoded Secrets, Memory Safety

### High Impact
- Insecure Crypto, Insecure Transport, SSRF, JWT Auth, CSRF
- Prototype Pollution, Unsafe Functions
- Terraform (AWS/Azure/GCP), Kubernetes, Docker, GitHub Actions

### Medium/Low Impact
- Regex DoS, Race Conditions, Code Correctness
- Best Practices, Performance, Maintainability

## Structure

```
code-security/
├── SKILL.md           # Skill definition (loaded by agents)
├── rules/             # Security rule files
│   ├── _sections.md   # Index of all categories
│   ├── _template.md   # Template for new rules
│   ├── sql-injection.md
│   ├── xss.md
│   └── ...            # 28 rule files total
├── metadata.json      # Skill metadata
└── README.md          # This file
```

## Usage

### For End Users

Install the skill:
```bash
npx skills add semgrep/skills
```

The agent will automatically reference these guidelines when writing or reviewing code.

### For Contributors

From the repo root:
```bash
make validate    # Validate all rule files
make build       # Build the skill
make zip         # Create distribution package
make             # All of the above
```

Or from the build package:
```bash
cd packages/skill-build
pnpm install
pnpm validate code-security    # Validate rule files
pnpm build-agents code-security  # Build AGENTS.md
```

## Creating a New Rule

1. Copy `rules/_template.md` to `rules/{category}.md`
2. Follow this structure:

````markdown
---
title: Rule Title
impact: HIGH
tags: security, category-name
---

## Rule Title

Brief explanation of the vulnerability.

**Incorrect (description):**

```python
# Vulnerable code
```

**Correct (description):**

```python
# Secure code
```
````

3. Run `make validate` to check formatting
4. Run `make` to rebuild everything

## Impact Levels

| Level | Description |
|-------|-------------|
| CRITICAL | Remote code execution, data breach |
| HIGH | Significant security risk |
| MEDIUM | Moderate risk, defense in depth |
| LOW | Best practices, code quality |

## Languages Supported

Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C/C++, C#, Scala, Kotlin, Rust, HCL (Terraform), YAML (Kubernetes/Docker)

## Acknowledgments

Created by [@DrewDennison](https://x.com/drewdennison) at [Semgrep](https://semgrep.dev).

Rules derived from [Semgrep Registry](https://semgrep.dev/r) with 2000+ security patterns.
