#!/usr/bin/env node
/**
 * Validate rule files follow the correct structure
 */

import { readdir } from 'fs/promises'
import { join } from 'path'
import { Rule } from './types.js'
import { parseRuleFile } from './parser.js'
import { RULES_DIR } from './config.js'

interface ValidationError {
  file: string
  ruleId?: string
  message: string
}

interface ValidationWarning {
  file: string
  message: string
}

interface ValidationResult {
  errors: ValidationError[]
  warnings: ValidationWarning[]
}

/**
 * Validate a rule
 */
function validateRule(rule: Rule, file: string): ValidationResult {
  const errors: ValidationError[] = []
  const warnings: ValidationWarning[] = []

  // Note: rule.id is auto-generated during build, not required in source files

  if (!rule.title || rule.title.trim().length === 0) {
    errors.push({ file, ruleId: rule.id, message: 'Missing or empty title' })
  }

  if (!rule.explanation || rule.explanation.trim().length === 0) {
    errors.push({ file, ruleId: rule.id, message: 'Missing or empty explanation' })
  }

  if (!rule.examples || rule.examples.length === 0) {
    errors.push({ file, ruleId: rule.id, message: 'Missing examples (need at least one bad and one good example)' })
  } else {
    // Filter out informational examples (notes, trade-offs, etc.) that don't have code
    const codeExamples = rule.examples.filter(e => e.code && e.code.trim().length > 0)

    const hasBad = codeExamples.some(e =>
      e.label.toLowerCase().includes('incorrect') ||
      e.label.toLowerCase().includes('wrong') ||
      e.label.toLowerCase().includes('bad')
    )
    const hasGood = codeExamples.some(e =>
      e.label.toLowerCase().includes('correct') ||
      e.label.toLowerCase().includes('good') ||
      e.label.toLowerCase().includes('usage') ||
      e.label.toLowerCase().includes('implementation') ||
      e.label.toLowerCase().includes('example')
    )

    if (codeExamples.length === 0) {
      errors.push({ file, ruleId: rule.id, message: 'Missing code examples' })
    } else if (!hasBad && !hasGood) {
      errors.push({ file, ruleId: rule.id, message: 'Missing bad/incorrect or good/correct examples' })
    }
  }

  const validImpacts: Rule['impact'][] = ['CRITICAL', 'HIGH', 'MEDIUM-HIGH', 'MEDIUM', 'LOW-MEDIUM', 'LOW']
  if (!validImpacts.includes(rule.impact)) {
    errors.push({ file, ruleId: rule.id, message: `Invalid impact level: ${rule.impact}. Must be one of: ${validImpacts.join(', ')}` })
  }

  // Warnings for missing optional fields
  if (!rule.impactDescription) {
    warnings.push({ file, message: 'Missing impactDescription field' })
  }

  if (!rule.tags || rule.tags.length === 0) {
    warnings.push({ file, message: 'Missing tags field' })
  }

  return { errors, warnings }
}

/**
 * Main validation function
 */
async function validate() {
  try {
    console.log('Validating rule files...')
    console.log(`Rules directory: ${RULES_DIR}`)

    const files = await readdir(RULES_DIR)
    const ruleFiles = files.filter(f => f.endsWith('.md') && !f.startsWith('_'))

    const allErrors: ValidationError[] = []
    const allWarnings: ValidationWarning[] = []

    for (const file of ruleFiles) {
      const filePath = join(RULES_DIR, file)
      try {
        const { rule } = await parseRuleFile(filePath)
        const { errors, warnings } = validateRule(rule, file)
        allErrors.push(...errors)
        allWarnings.push(...warnings)
      } catch (error) {
        allErrors.push({
          file,
          message: `Failed to parse: ${error instanceof Error ? error.message : String(error)}`
        })
      }
    }

    // Report warnings (non-fatal)
    if (allWarnings.length > 0) {
      console.log(`\n⚠ Warnings (${allWarnings.length}):\n`)
      allWarnings.forEach(warning => {
        console.log(`  ${warning.file}: ${warning.message}`)
      })
    }

    // Report errors (fatal)
    if (allErrors.length > 0) {
      console.error('\n✗ Validation failed:\n')
      allErrors.forEach(error => {
        console.error(`  ${error.file}${error.ruleId ? ` (${error.ruleId})` : ''}: ${error.message}`)
      })
      process.exit(1)
    } else {
      console.log(`\n✓ All ${ruleFiles.length} rule files are valid`)
      if (allWarnings.length > 0) {
        console.log(`  (${allWarnings.length} warnings - consider adding missing optional fields)`)
      }
    }
  } catch (error) {
    console.error('Validation failed:', error)
    process.exit(1)
  }
}

validate()
