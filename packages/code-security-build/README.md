# Code Security Build Tools

Build tooling for validating, compiling, and testing the code-security skill.

## Overview

This package provides tools to:
- **Validate** rule files follow the correct format
- **Build** compiled outputs (AGENTS.md, test-cases.json)
- **Extract** test cases for LLM evaluation

## Installation

```bash
pnpm install
```

## Scripts

| Command | Description |
|---------|-------------|
| `pnpm validate` | Validate all rule files in `skills/code-security/rules/` |
| `pnpm build` | Build AGENTS.md and extract test cases |
| `pnpm build-agents` | Build only AGENTS.md |
| `pnpm extract-tests` | Extract test cases to JSON |
| `pnpm dev` | Build and validate |

## Rule Validation

The validator checks that each rule file has:
- Valid frontmatter with `title` and `impact`
- Main heading using `##`
- At least one `**Incorrect:**` example with code
- At least one `**Correct:**` example with code
- Valid impact level (CRITICAL, HIGH, MEDIUM, LOW)

### Example Valid Rule

```markdown
---
title: Prevent SQL Injection
impact: CRITICAL
tags: security, sql
---

## Prevent SQL Injection

Never concatenate user input into SQL queries.

**Incorrect (vulnerable):**

```python
query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Correct (parameterized):**

```python
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```
```

## Architecture

```
src/
├── validate.ts      # Rule file validation
├── build.ts         # AGENTS.md compilation
├── extract-tests.ts # Test case extraction
├── parser.ts        # Markdown parser for rules
├── types.ts         # TypeScript type definitions
└── config.ts        # Configuration (paths, etc.)
```

## Configuration

Rules are read from: `../../skills/code-security/rules/`

Files starting with `_` are excluded (e.g., `_template.md`, `_sections.md`).

## Usage from Root

You can also use the Makefile from the repo root:

```bash
make validate   # Runs pnpm validate
make build      # Runs pnpm build
make zip        # Creates skill zip package
make            # All of the above
```

## Development

```bash
# Run validation during development
pnpm dev

# Just validate
pnpm validate

# Full build
pnpm build
```
