# Semgrep Skill

Run Semgrep static analysis scans and create custom detection rules for security vulnerabilities and bug patterns.

## Capabilities

### Running Scans
- Quick scans with `semgrep --config auto`
- Curated rulesets: security-audit, owasp-top-ten, cwe-top-25, trailofbits
- Multiple output formats: text, SARIF, JSON
- Data flow traces for debugging

### Creating Custom Rules
- Pattern matching for syntactic detection
- Taint mode for data flow vulnerabilities
- Test-driven rule development
- AST analysis for precise patterns

## Structure

```
semgrep/
├── SKILL.md              # Main skill definition
├── references/
│   ├── workflow.md       # Detailed rule creation workflow
│   └── quick-reference.md # Pattern syntax and taint components
└── README.md             # This file
```

## Usage

### For End Users

Install the skill:
```bash
npx skills add semgrep/skills
```

The agent will use this skill when you ask to:
- Scan code with Semgrep
- Create custom detection rules
- Find security vulnerabilities
- Set up Semgrep in CI/CD

### Example Prompts

```
Scan this Python file for security issues with Semgrep
```
```
Create a Semgrep rule to detect hardcoded API keys
```
```
Write a taint mode rule for SQL injection in Flask
```

## Rule Creation Workflow

1. **Analyze** - Understand the bug pattern, choose taint vs pattern approach
2. **Test First** - Write `ruleid:` and `ok:` test annotations
3. **AST Analysis** - Run `semgrep --dump-ast` to understand code structure
4. **Write Rule** - Start simple, iterate
5. **Validate** - Run `semgrep --test` until 100% pass
6. **Optimize** - Remove redundant patterns after tests pass

## When to Use Taint Mode

Use `mode: taint` for injection vulnerabilities where untrusted data flows to dangerous sinks:

| Vulnerability | Source | Sink |
|--------------|--------|------|
| SQL Injection | `request.args` | `cursor.execute()` |
| Command Injection | `request.form` | `os.system()` |
| XSS | User input | `render_template_string()` |
| Path Traversal | URL params | `open()` |
| SSRF | User input | `requests.get()` |

## When to Use Pattern Matching

Use basic patterns for syntactic detection without data flow:

- Deprecated or dangerous functions (`eval`, `exec`)
- Hardcoded credentials
- Missing security headers
- Configuration issues

## Quick Reference

| Command | Purpose |
|---------|---------|
| `semgrep --config auto .` | Quick scan |
| `semgrep --config p/security-audit .` | Use ruleset |
| `semgrep --test --config rule.yaml test-file` | Run tests |
| `semgrep --validate --config rule.yaml` | Validate YAML |
| `semgrep --dump-ast -l python file.py` | Show AST |
| `semgrep --dataflow-traces -f rule.yaml file` | Debug taint |

## Resources

- [Semgrep Registry](https://semgrep.dev/explore) - Browse existing rules
- [Semgrep Playground](https://semgrep.dev/playground) - Test rules online
- [Semgrep Docs](https://semgrep.dev/docs/) - Official documentation
- [Trail of Bits Rules](https://github.com/trailofbits/semgrep-rules) - Security-focused rules

## Acknowledgments

Based on skills from [Trail of Bits](https://github.com/trailofbits/skills):
- `semgrep` - Static analysis scanning
- `semgrep-rule-creator` - Custom rule development
