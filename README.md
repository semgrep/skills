# Agent Skills

A collection of skills for AI coding agents. Skills are packaged instructions and scripts that extend agent capabilities.

Skills follow the [Agent Skills](https://agentskills.io/) format.

## Available Skills

### code-security

Code security guidelines from Semgrep Engineering. 

**Use when:**
- Writing new code
- Reviewing code for security issues

**Categories covered:**
- SQL Injection (Critical)

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