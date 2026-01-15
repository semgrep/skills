---
name: code-security
description: Security guidelines for writing secure code. Use when writing code, reviewing code for vulnerabilities, or asking about secure coding practices like "check for SQL injection" or "review security".
---

# Code Security Guidelines

Comprehensive security rules for writing secure code across multiple languages and frameworks. Covers OWASP Top 10 vulnerabilities, infrastructure security, and coding best practices.

## How It Works

1. When you write or review code, reference these security guidelines
2. Each rule includes incorrect (vulnerable) and correct (secure) code examples
3. Rules are organized by vulnerability category and impact level

## Categories

### Critical Impact
- **SQL Injection** - Use parameterized queries, never concatenate user input
- **Command Injection** - Avoid shell commands with user input, use safe APIs
- **XSS** - Escape output, use framework protections
- **XXE** - Disable external entities in XML parsers
- **Path Traversal** - Validate and sanitize file paths
- **Insecure Deserialization** - Never deserialize untrusted data
- **Code Injection** - Never eval() user input
- **Hardcoded Secrets** - Use environment variables or secret managers
- **Memory Safety** - Prevent buffer overflows, use-after-free (C/C++)

### High Impact
- **Insecure Crypto** - Use SHA-256+, AES-256, avoid MD5/SHA1/DES
- **Insecure Transport** - Use HTTPS, verify certificates
- **SSRF** - Validate URLs, use allowlists
- **JWT Issues** - Always verify signatures
- **CSRF** - Use CSRF tokens on state-changing requests
- **Prototype Pollution** - Validate object keys in JavaScript

### Infrastructure
- **Terraform AWS/Azure/GCP** - Encryption, least privilege, no public access
- **Kubernetes** - No privileged containers, run as non-root
- **Docker** - Don't run as root, pin image versions
- **GitHub Actions** - Avoid script injection, pin action versions

## Usage

Reference the rules in `rules/` directory for detailed examples:

- `rules/sql-injection.md` - SQL injection prevention
- `rules/xss.md` - Cross-site scripting prevention
- `rules/command-injection.md` - Command injection prevention
- `rules/_sections.md` - Full index of all 28 rule categories

## Quick Reference

| Vulnerability | Key Prevention |
|--------------|----------------|
| SQL Injection | Parameterized queries |
| XSS | Output encoding |
| Command Injection | Avoid shell, use APIs |
| Path Traversal | Validate paths |
| SSRF | URL allowlists |
| Secrets | Environment variables |
| Crypto | SHA-256, AES-256 |
