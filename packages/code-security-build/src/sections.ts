/**
 * Parse _sections.md to extract section metadata dynamically
 * This eliminates hardcoded section mappings throughout the codebase
 */

import { readFile } from 'fs/promises'
import { join } from 'path'
import { ImpactLevel } from './types.js'
import { RULES_DIR } from './config.js'

export interface SectionMetadata {
  number: number
  title: string
  filename: string
  impact: ImpactLevel
  description: string
}

let cachedSections: SectionMetadata[] | null = null
let cachedFilenameMap: Map<string, number> | null = null

/**
 * Parse _sections.md and return all section metadata
 */
export async function parseSectionsFile(): Promise<SectionMetadata[]> {
  if (cachedSections) {
    return cachedSections
  }

  const sectionsFile = join(RULES_DIR, '_sections.md')
  const content = await readFile(sectionsFile, 'utf-8')

  const sections: SectionMetadata[] = []

  // Split by section headers: ### 1. Title (filename)
  const sectionBlocks = content.split(/(?=^### \d+\. )/m).filter(Boolean)

  for (const block of sectionBlocks) {
    // Extract section number, title, and filename from header
    // Format: ### 1. SQL Injection (sql-injection)
    const headerMatch = block.match(/^### (\d+)\.\s+(.+?)\s+\(([^)]+)\)$/m)
    if (!headerMatch) continue

    const number = parseInt(headerMatch[1])
    const title = headerMatch[2].trim()
    const filename = headerMatch[3].trim()

    // Extract impact (format: **Impact:** CRITICAL)
    const impactMatch = block.match(/\*\*Impact:\*\*\s+(\w+)/i)
    const impact = impactMatch
      ? (impactMatch[1].toUpperCase() as ImpactLevel)
      : 'MEDIUM'

    // Extract description (format: **Description:** text)
    const descMatch = block.match(/\*\*Description:\*\*\s+(.+?)(?=\n\n|\n###|$)/s)
    const description = descMatch ? descMatch[1].trim() : ''

    sections.push({
      number,
      title,
      filename,
      impact,
      description,
    })
  }

  cachedSections = sections
  return sections
}

/**
 * Get a mapping from filename (without .md) to section number
 */
export async function getFilenameToSectionMap(): Promise<Map<string, number>> {
  if (cachedFilenameMap) {
    return cachedFilenameMap
  }

  const sections = await parseSectionsFile()
  const map = new Map<string, number>()

  for (const section of sections) {
    map.set(section.filename, section.number)
  }

  cachedFilenameMap = map
  return map
}

/**
 * Get section number for a given filename
 */
export async function getSectionForFilename(filename: string): Promise<number> {
  const map = await getFilenameToSectionMap()
  // Remove .md extension if present
  const key = filename.replace(/\.md$/, '')
  return map.get(key) || 0
}

/**
 * Get section metadata by number
 */
export async function getSectionByNumber(num: number): Promise<SectionMetadata | undefined> {
  const sections = await parseSectionsFile()
  return sections.find(s => s.number === num)
}

/**
 * Clear cached data (useful for testing)
 */
export function clearCache(): void {
  cachedSections = null
  cachedFilenameMap = null
}
