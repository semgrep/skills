/**
 * AST-based parser for rule markdown files using remark/unified
 */

import { readFile } from 'fs/promises'
import { unified } from 'unified'
import remarkParse from 'remark-parse'
import remarkFrontmatter from 'remark-frontmatter'
import { visit } from 'unist-util-visit'
import yaml from 'js-yaml'
import type { Root, Code, Heading, Paragraph, Strong, Text, Link } from 'mdast'
import { Rule, ImpactLevel, CodeExample } from './types.js'
import { getSectionForFilename } from './sections.js'

export interface RuleFile {
  section: number
  subsection?: number
  rule: Rule
}

interface Frontmatter {
  title?: string
  impact?: string
  impactDescription?: string
  tags?: string
  section?: number
  explanation?: string
  references?: string
}

/**
 * Extract text content from a paragraph or heading node
 */
function extractText(node: Paragraph | Heading): string {
  let text = ''
  for (const child of node.children) {
    if (child.type === 'text') {
      text += child.value
    } else if (child.type === 'strong' || child.type === 'emphasis') {
      text += extractText({ type: 'paragraph', children: child.children } as Paragraph)
    } else if (child.type === 'inlineCode') {
      text += child.value
    } else if (child.type === 'link') {
      text += extractText({ type: 'paragraph', children: child.children } as Paragraph)
    }
  }
  return text
}

/**
 * Check if a paragraph node is an example label (e.g., **Incorrect:** or **Correct (description):**)
 */
function isExampleLabel(node: Paragraph): { label: string; description?: string } | null {
  // An example label should be a single strong element ending with colon
  if (node.children.length !== 1 && node.children.length !== 2) {
    // Allow for trailing whitespace text node
    if (node.children.length === 2 && node.children[1].type === 'text') {
      const text = (node.children[1] as Text).value.trim()
      if (text !== '' && text !== ':') return null
    } else {
      return null
    }
  }

  const firstChild = node.children[0]
  if (firstChild.type !== 'strong') return null

  const strongText = extractText({ type: 'paragraph', children: (firstChild as Strong).children } as Paragraph)

  // Must end with colon (possibly with the colon outside the strong)
  let fullText = strongText
  if (node.children.length === 2 && node.children[1].type === 'text') {
    fullText += (node.children[1] as Text).value
  }

  // Check if it ends with colon (allowing for trailing whitespace)
  if (!fullText.trim().endsWith(':')) return null

  // Remove trailing colon for label extraction
  const labelText = fullText.trim().slice(0, -1).trim()

  // Try to extract description from parentheses
  const descMatch = labelText.match(/^([A-Za-z]+(?:\s+[A-Za-z]+)*)\s*\(([^()]+)\)$/)
  if (descMatch) {
    return {
      label: descMatch[1].trim(),
      description: descMatch[2].trim()
    }
  }

  return { label: labelText }
}

/**
 * Check if a paragraph contains reference links
 */
function isReferenceLine(node: Paragraph): string[] | null {
  const text = extractText(node)
  if (!text.startsWith('**References:**') && !text.startsWith('References:') && !text.startsWith('Reference:')) {
    return null
  }

  const refs: string[] = []
  visit(node, 'link', (linkNode: Link) => {
    refs.push(linkNode.url)
  })

  return refs.length > 0 ? refs : null
}

/**
 * Parse a rule markdown file into a Rule object using AST
 */
export async function parseRuleFile(filePath: string): Promise<RuleFile> {
  const content = await readFile(filePath, 'utf-8')

  // Parse markdown with frontmatter support
  const processor = unified()
    .use(remarkParse)
    .use(remarkFrontmatter, ['yaml'])

  const tree = processor.parse(content) as Root

  // Extract frontmatter
  let frontmatter: Frontmatter = {}
  visit(tree, 'yaml', (node) => {
    try {
      frontmatter = yaml.load((node as any).value) as Frontmatter || {}
    } catch (e) {
      // Ignore YAML parse errors
    }
  })

  // Parse content
  let title = ''
  let explanation = ''
  const examples: CodeExample[] = []
  const references: string[] = []

  let currentExample: CodeExample | null = null
  let foundTitle = false
  let inExampleSection = false

  // Get all non-frontmatter children
  const children = tree.children.filter(child => child.type !== 'yaml')

  for (let i = 0; i < children.length; i++) {
    const node = children[i]

    // Extract title from first heading
    if (node.type === 'heading' && !foundTitle) {
      title = extractText(node)
      foundTitle = true
      continue
    }

    // Check for example labels
    if (node.type === 'paragraph') {
      const labelInfo = isExampleLabel(node)
      if (labelInfo) {
        // Save previous example
        if (currentExample) {
          examples.push(currentExample)
        }
        currentExample = {
          label: labelInfo.label,
          description: labelInfo.description,
          code: '',
          language: 'typescript'
        }
        inExampleSection = true
        continue
      }

      // Check for references
      const refs = isReferenceLine(node)
      if (refs) {
        // Save current example before processing references
        if (currentExample) {
          examples.push(currentExample)
          currentExample = null
        }
        references.push(...refs)
        inExampleSection = false
        continue
      }

      // Regular paragraph - either explanation or additional text
      const text = extractText(node)
      if (!inExampleSection && !currentExample) {
        // Main explanation before any examples
        if (text.trim()) {
          explanation += (explanation ? '\n\n' : '') + text
        }
      } else if (currentExample && currentExample.code) {
        // Additional text after code block
        if (text.trim()) {
          currentExample.additionalText = (currentExample.additionalText || '') +
            (currentExample.additionalText ? '\n\n' : '') + text
        }
      }
    }

    // Extract code blocks
    if (node.type === 'code' && currentExample) {
      const codeNode = node as Code
      currentExample.code = codeNode.value
      currentExample.language = codeNode.lang || 'typescript'
    }
  }

  // Save last example
  if (currentExample) {
    examples.push(currentExample)
  }

  // Get section number from _sections.md (parsed dynamically)
  const filename = filePath.split('/').pop() || ''
  const section = frontmatter.section || await getSectionForFilename(filename)

  const rule: Rule = {
    id: '', // Will be assigned by build script based on sorted order
    title: frontmatter.title || title,
    section: section,
    subsection: undefined,
    impact: (frontmatter.impact?.toUpperCase() || 'MEDIUM') as ImpactLevel,
    impactDescription: frontmatter.impactDescription || '',
    explanation: frontmatter.explanation || explanation.trim(),
    examples,
    references: frontmatter.references
      ? frontmatter.references.split(',').map((r: string) => r.trim())
      : references,
    tags: frontmatter.tags
      ? frontmatter.tags.split(',').map((t: string) => t.trim())
      : undefined,
  }

  return {
    section,
    subsection: 0,
    rule,
  }
}
