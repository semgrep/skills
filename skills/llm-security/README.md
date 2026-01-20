# LLM Security Skill

Security guidelines for LLM applications based on the OWASP Top 10 for Large Language Model Applications 2025.

## Categories (10 Total)

### Critical Impact
- **LLM01: Prompt Injection** - Input validation, content segregation, output filtering
- **LLM02: Sensitive Information Disclosure** - Data sanitization, PII detection, permission-aware RAG
- **LLM03: Supply Chain** - Model verification, safetensors, ML-BOM
- **LLM04: Data and Model Poisoning** - Training data validation, anomaly detection
- **LLM05: Improper Output Handling** - Context-aware encoding, parameterized queries

### High Impact
- **LLM06: Excessive Agency** - Least privilege, human-in-the-loop, rate limiting
- **LLM07: System Prompt Leakage** - External guardrails, no secrets in prompts
- **LLM08: Vector and Embedding Weaknesses** - Permission-aware retrieval, tenant isolation
- **LLM09: Misinformation** - RAG, fact verification, confidence scoring
- **LLM10: Unbounded Consumption** - Input limits, budget controls, model theft detection

## Structure

```
llm-security/
├── SKILL.md           # Skill definition (loaded by agents)
├── rules/             # Security rule files
│   ├── _sections.md   # Index of all categories
│   ├── prompt-injection.md
│   ├── sensitive-disclosure.md
│   └── ...            # 10 rule files total
└── README.md          # This file
```

## Usage

### For End Users

Install the skill:
```bash
npx skills add semgrep/skills
```

The agent will automatically reference these guidelines when building or reviewing LLM applications.

### For Contributors

From the repo root:
```bash
make validate    # Validate all skills
make build       # Build all skills
make zip         # Create distribution packages
make             # All of the above
```

Or for this skill only:
```bash
cd packages/skill-build
pnpm install
pnpm validate llm-security      # Validate rule files
pnpm build-agents llm-security  # Build AGENTS.md
```

## Creating a New Rule

1. Create `rules/{category}.md`
2. Follow this structure:

````markdown
---
title: Category Title
impact: HIGH
impactDescription: Brief description of the impact
tags: security, llm, category-name, owasp-llmXX
---

## Category Title

Brief explanation of the vulnerability.

**Vulnerable (description):**

```python
# Vulnerable code
```

**Secure (description):**

```python
# Secure code
```
````

3. Add entry to `rules/_sections.md`
4. Run `make validate` to check formatting
5. Run `make` to rebuild everything

## Impact Levels

| Level | Description |
|-------|-------------|
| CRITICAL | Data exfiltration, model compromise, unauthorized actions |
| HIGH | Information disclosure, service degradation, significant risk |

## Related Frameworks

- **OWASP Top 10 for LLM Applications 2025** - Primary source
- **MITRE ATLAS** - Adversarial Threat Landscape for AI Systems
- **NIST AI RMF** - AI Risk Management Framework

## References

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)

## Acknowledgments

Created by [@DrewDennison](https://x.com/drewdennison) at [Semgrep](https://semgrep.dev).

Rules derived from the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
