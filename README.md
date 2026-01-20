# Agent Skills

A collection of skills for AI coding agents. Skills are packaged instructions and scripts that extend agent capabilities.

Skills follow the [Agent Skills](https://agentskills.io/) format.

## Installation

```bash
npx skills add semgrep/skills
```

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

---

### llm-security

Security guidelines for LLM applications based on the OWASP Top 10 for Large Language Model Applications 2025.

**Use when:**
- Building LLM-powered applications
- Implementing RAG systems
- Securing AI/ML pipelines
- Reviewing code that interacts with language models

**Categories covered:**

| Impact | Category | Description |
|--------|----------|-------------|
| **Critical** | Prompt Injection | Input validation, content segregation, output filtering |
| **Critical** | Sensitive Information Disclosure | PII detection, permission-aware RAG |
| **Critical** | Supply Chain | Model verification, safetensors, ML-BOM |
| **Critical** | Data and Model Poisoning | Training data validation, anomaly detection |
| **Critical** | Improper Output Handling | Context-aware encoding, parameterized queries |
| **High** | Excessive Agency | Least privilege, human-in-the-loop |
| **High** | System Prompt Leakage | External guardrails, no secrets in prompts |
| **High** | Vector and Embedding Weaknesses | Permission-aware retrieval, tenant isolation |
| **High** | Misinformation | RAG, fact verification, confidence scoring |
| **High** | Unbounded Consumption | Rate limiting, budget controls |

**Frameworks:** OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF

---


## Usage

Skills are automatically available once installed. The agent will use them when relevant tasks are detected.

**Examples:**
```
Review this React component for security issues
```
```
Help me implement input validation for my LLM chat endpoint
```

## Development

### Building Skills

```bash
make install     # Install dependencies
make validate    # Validate all skills
make build       # Build AGENTS.md for all skills
make zip         # Create distribution packages
make             # All of the above
```

### Single Skill Operations

```bash
make validate-skill SKILL=code-security
make build-skill SKILL=llm-security
```

## Skill Structure

Each skill contains:
- `SKILL.md` - Instructions for the agent
- `rules/` - Individual rule files (for skills with rules)
- `scripts/` - Helper scripts for automation (optional)
- `references/` - Supporting documentation (optional)

## Acknowledgments

Originally created by [@DrewDennison](https://x.com/drewdennison) at [Semgrep](https://semgrep.dev). This work was heavily inspired by Vercel's [React Best Practices](https://vercel.com/blog/introducing-react-best-practices).
