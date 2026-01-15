# Code Security

A structured repository for creating and maintaining Code Security Best Practices optimized for agents and LLMs.

## Structure

- `rules/` - Individual rule files (one per rule)
  - `_sections.md` - Section metadata (titles, impacts, descriptions)
  - `_template.md` - Template for creating new rules
  - `{area}-{description}.md` - Individual rule files
- `metadata.json` - Document metadata (version, organization, abstract)
- __`AGENTS.md`__ - Compiled output (generated)
- __`test-cases.json`__ - Test cases for LLM evaluation (generated)

## Getting Started

1. Change to build package
   ```bash
   cd packages/code-security-build
   ```

1. Install dependencies:
   ```bash
   pnpm install
   ```

1. Build AGENTS.md from rules:
   ```bash
   pnpm build
   ```

1. Validate rule files:
   ```bash
   pnpm validate
   ```

1. Extract test cases:
   ```bash
   pnpm extract-tests
   ```

## Creating a New Rule

1. Copy `rules/_template.md` to `rules/{area}-{description}.md`
2. Choose the appropriate area prefix:
   - `sql-` for SQL security (Section 1)
3. Fill in the frontmatter and content
4. Ensure you have clear examples with explanations
5. Run `pnpm build` from the build package to regenerate AGENTS.md and test-cases.json

## Rule File Structure

Each rule file should follow this structure:

```markdown
---
title: Rule Title Here
impact: MEDIUM
impactDescription: Optional description
tags: tag1, tag2, tag3
---

## Rule Title Here

Brief explanation of the rule and why it matters.

**Incorrect (description of what's wrong):**

```typescript
// Bad code example
```

**Correct (description of what's right):**

```typescript
// Good code example
```

Optional explanatory text after examples.

Reference: [Link](https://example.com)

## File Naming Convention

- Files starting with `_` are special (excluded from build)
- Rule files: `area-description.md` (e.g., `sql-injection.md`)
- Section is automatically inferred from filename prefix
- Rules are sorted alphabetically by title within each section
- IDs (e.g., 1.1, 1.2) are auto-generated during build

## Impact Levels

- `CRITICAL` - Highest priority, major security gains
- `HIGH` - Significant security improvements
- `MEDIUM-HIGH` - Moderate-high gains
- `MEDIUM` - Moderate security improvements
- `LOW-MEDIUM` - Low-medium gains
- `LOW` - Incremental improvements

## Scripts

- `pnpm build` - Compile rules into AGENTS.md
- `pnpm validate` - Validate all rule files
- `pnpm extract-tests` - Extract test cases for LLM evaluation
- `pnpm dev` - Build and validate

## Contributing

When adding or modifying rules:

1. Use the correct filename prefix for your section
2. Follow the `_template.md` structure
3. Include clear bad/good examples with explanations
4. Add appropriate tags
5. Run `pnpm build` to regenerate AGENTS.md and test-cases.json
6. Rules are automatically sorted by title - no need to manage numbers!

## Acknowledgments

Originally created by [@DrewDennison](https://x.com/drewdennison) at [Semgrep](https://semgrep.dev). This work was heavily inspired by Vercel's [React Best Practices](https://vercel.com/blog/introducing-react-best-practices)