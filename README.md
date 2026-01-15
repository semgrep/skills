# Agent Skills

A collection of skills for AI coding agents. Skills are packaged instructions and scripts that extend agent capabilities.

Skills follow the [Agent Skills](https://agentskills.io/) format.

## Available Skills

### code-security

Comprehensive code security guidelines from Semgrep Engineering covering OWASP Top 10, infrastructure security, and secure coding best practices across 15+ languages.

**Use when:**
- Writing new code
- Reviewing code for security vulnerabilities
- Asking about secure coding practices
- Configuring cloud infrastructure (Terraform, Kubernetes, Docker)

**Categories covered:**

| Impact | Category | Description |
|--------|----------|-------------|
| **Critical** | SQL Injection | Parameterized queries, ORM safety |
| **Critical** | Command Injection | Shell command safety, input validation |
| **Critical** | Cross-Site Scripting (XSS) | Output encoding, DOM safety |
| **Critical** | XML External Entity (XXE) | XML parser configuration |
| **Critical** | Path Traversal | File path validation |
| **Critical** | Insecure Deserialization | Safe deserialization patterns |
| **Critical** | Code Injection | Eval safety, template injection |
| **Critical** | Hardcoded Secrets | Environment variables, secret management |
| **Critical** | Memory Safety | Buffer overflows, use-after-free (C/C++) |
| **High** | Insecure Cryptography | Strong hashing (SHA-256+), encryption (AES) |
| **High** | Insecure Transport | HTTPS, certificate validation, TLS |
| **High** | Server-Side Request Forgery | URL validation, allowlists |
| **High** | JWT Authentication | Signature verification, algorithm safety |
| **High** | Cross-Site Request Forgery | CSRF tokens, SameSite cookies |
| **High** | Prototype Pollution | Object key validation (JavaScript) |
| **High** | Unsafe Functions | Dangerous function alternatives |
| **High** | Terraform AWS | S3, IAM, EC2, RDS security |
| **High** | Terraform Azure | Storage, App Service, Key Vault |
| **High** | Terraform GCP | GCS, GCE, GKE, IAM |
| **High** | Kubernetes | Pod security, RBAC, secrets |
| **High** | Docker | Non-root containers, image pinning |
| **High** | GitHub Actions | Script injection, action pinning |
| **Medium** | Regex DoS | Catastrophic backtracking prevention |
| **Medium** | Race Conditions | TOCTOU, secure temp files |
| **Medium** | Code Correctness | Common bugs, type errors |
| **Low** | Best Practices | Code quality patterns |
| **Low** | Performance | Efficiency anti-patterns |
| **Low** | Maintainability | Code organization |

**Languages:** Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C/C++, C#, Scala, Kotlin, Rust, HCL (Terraform), YAML (Kubernetes)

## Installation

```bash
npx add-skill semgrep/agent-skills
```

## Usage

Skills are automatically available once installed. The agent will use them when relevant tasks are detected.

**Examples:**
```
Review this React component for security issues
```


## Skill Structure

Each skill contains:
- `SKILL.md` - Instructions for the agent
- `scripts/` - Helper scripts for automation (optional)
- `references/` - Supporting documentation (optional)

## Acknowledgments

Originally created by [@DrewDennison](https://x.com/drewdennison) at [Semgrep](https://semgrep.dev). This work was heavily inspired by Vercel's [React Best Practices](https://vercel.com/blog/introducing-react-best-practices)