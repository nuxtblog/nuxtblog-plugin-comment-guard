#!/usr/bin/env node
/**
 * Submit PR to nuxtblog/registry — create or update plugin entry.
 * Reads metadata from plugin.yaml (not package.json).
 *
 * Requirements:
 *   - GitHub CLI (gh) authenticated
 *   - REGISTRY_PAT secret with repo scope
 */

import { readFileSync, writeFileSync, unlinkSync } from 'fs'
import { execSync } from 'child_process'
import { tmpdir } from 'os'
import { join } from 'path'

const REGISTRY_REPO = 'nuxtblog/registry'

function run(cmd) {
  return execSync(cmd, { encoding: 'utf-8' }).trim()
}

function runSilent(cmd) {
  try { return execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim() }
  catch { return null }
}

// ── Parse plugin.yaml (simple top-level keys only) ────────────────────────────

function parsePluginYaml(filePath) {
  const content = readFileSync(filePath, 'utf-8')
  const result = {}
  for (const line of content.split('\n')) {
    const m = line.match(/^(\w[\w_]*)\s*:\s*(.+)$/)
    if (!m) continue
    let val = m[2].trim()
    // strip quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'")))
      val = val.slice(1, -1)
    // parse inline array [a, b, c]
    if (val.startsWith('[') && val.endsWith(']')) {
      val = val.slice(1, -1).split(',').map(s => s.trim().replace(/^["']|["']$/g, ''))
    }
    result[m[1]] = val
  }
  return result
}

const p = parsePluginYaml('plugin.yaml')

// ── Derive repo info ──────────────────────────────────────────────────────────

const remoteUrl = run('git remote get-url origin')
const repoMatch = remoteUrl.match(/[:/]([\w.-]+\/[\w.-]+?)(?:\.git)?$/)
if (!repoMatch) {
  console.error('Cannot parse git remote URL:', remoteUrl)
  process.exit(1)
}
const pluginRepo = repoMatch[1]
const pluginOwner = pluginRepo.split('/')[0]
const pluginId = p.id

const fileBaseName = `${pluginOwner}_${pluginId}`
const pluginFilePath = `plugins/${fileBaseName}.json`

// ── Get GitHub username ───────────────────────────────────────────────────────

let username
try {
  username = run('gh api user --jq .login')
} catch {
  console.error('GitHub CLI not authenticated. Run: gh auth login')
  process.exit(1)
}

console.log(`\nPlugin : ${pluginId} v${p.version}`)
console.log(`Repo   : ${pluginRepo}`)
console.log(`File   : ${pluginFilePath}`)
console.log(`User   : ${username}`)
console.log(`Target : ${REGISTRY_REPO}\n`)

// ── Fork registry if needed ───────────────────────────────────────────────────

console.log('Ensuring fork exists...')
runSilent(`gh repo fork ${REGISTRY_REPO} --clone=false`)

console.log('Syncing fork with upstream...')
runSilent(`gh repo sync ${username}/registry`)

// ── Check existing entry ──────────────────────────────────────────────────────

let existingEntry = null

const existingRaw = runSilent(`gh api "repos/${REGISTRY_REPO}/contents/${pluginFilePath}"`)
if (existingRaw) {
  try {
    const fileInfo = JSON.parse(existingRaw)
    existingEntry = JSON.parse(Buffer.from(fileInfo.content, 'base64').toString())
  } catch {}
}

// ── Validate ──────────────────────────────────────────────────────────────────

if (existingEntry && existingEntry.repo !== pluginRepo) {
  console.error(`\n❌ Name conflict: "${pluginId}" is already registered by ${existingEntry.repo}`)
  process.exit(1)
}

if (existingEntry) {
  const semver = v => v.replace(/^v/, '').split('.').map(Number)
  const [eMaj, eMin, ePat] = semver(existingEntry.version)
  const [nMaj, nMin, nPat] = semver(p.version)
  const isNewer =
    nMaj > eMaj ||
    (nMaj === eMaj && nMin > eMin) ||
    (nMaj === eMaj && nMin === eMin && nPat > ePat)
  if (!isNewer) {
    console.error(`\n❌ Version regression: registry has v${existingEntry.version}, cannot publish v${p.version}`)
    process.exit(1)
  }
}

// ── Build entry ───────────────────────────────────────────────────────────────

const now = new Date().toISOString()
const tags = Array.isArray(p.tags) ? p.tags : []

const entry = {
  name:         pluginId,
  title:        p.title || '',
  description:  p.description || '',
  version:      p.version,
  author:       p.author || username,
  icon:         p.icon || 'i-tabler-plug',
  repo:         pluginRepo,
  homepage:     `https://github.com/${pluginRepo}`,
  tags,
  type:         p.type || 'js',
  runtime:      p.runtime || 'interpreted',
  is_official:  existingEntry?.is_official ?? (p.trust_level === 'official'),
  license:      p.license || 'MIT',
  sdk_version:  p.sdk_version || '1.0.0',
  trust_level:  p.trust_level || 'community',
  capabilities: existingEntry?.capabilities ?? [],
  features:     existingEntry?.features ?? [],
  published_at: existingEntry?.published_at ?? now,
  updated_at:   now,
}

console.log(existingEntry ? `Updating entry: ${pluginId}` : `Adding new entry: ${pluginId}`)

// ── Create branch in fork ─────────────────────────────────────────────────────

const branch = `plugin/${pluginId}-v${p.version}`
const defaultBranch = run(`gh api repos/${username}/registry --jq .default_branch`).replace(/^"|"$/g, '')
const branchSha = JSON.parse(
  run(`gh api repos/${username}/registry/branches/${defaultBranch}`)
).commit.sha

runSilent(
  `gh api repos/${username}/registry/git/refs --method POST -f ref=refs/heads/${branch} -f sha=${branchSha}`
)
console.log(`Branch: ${branch}`)

// ── Commit plugin file to fork branch ─────────────────────────────────────────

let forkFileSha = null
const forkFileRaw = runSilent(`gh api "repos/${username}/registry/contents/${pluginFilePath}?ref=${branch}"`)
if (forkFileRaw) {
  try { forkFileSha = JSON.parse(forkFileRaw).sha } catch {}
}

const newContent = Buffer.from(JSON.stringify(entry, null, 2) + '\n').toString('base64')
const commitMsg = existingEntry
  ? `chore: update ${pluginId} to v${p.version}`
  : `feat: add ${pluginId} v${p.version}`

const tmpFile = join(tmpdir(), 'plugin-entry-payload.json')
const payload = { message: commitMsg, content: newContent, branch }
if (forkFileSha) payload.sha = forkFileSha

writeFileSync(tmpFile, JSON.stringify(payload))
run(`gh api repos/${username}/registry/contents/${pluginFilePath} --method PUT --input "${tmpFile}"`)
unlinkSync(tmpFile)
console.log(`Committed ${pluginFilePath} to fork`)

// ── Open PR ───────────────────────────────────────────────────────────────────

const prTitle = existingEntry
  ? `chore: update ${pluginId} to v${p.version}`
  : `feat: add ${pluginId} v${p.version}`

const prBody = [
  '## Plugin Submission',
  '',
  '| Field | Value |',
  '|---|---|',
  `| Name | \`${pluginId}\` |`,
  `| Version | \`${p.version}\` |`,
  `| Type | \`${entry.type}\` |`,
  `| Repo | [\`${pluginRepo}\`](https://github.com/${pluginRepo}) |`,
  '',
  p.description || '',
].join('\n')

const prPayload = join(tmpdir(), 'pr-payload.json')
writeFileSync(prPayload, JSON.stringify({
  title: prTitle,
  body:  prBody,
  head:  `${username}:${branch}`,
  base:  'main',
}))

try {
  const pr = JSON.parse(run(`gh api repos/${REGISTRY_REPO}/pulls --method POST --input "${prPayload}"`))
  console.log(`\n✅ PR created: ${pr.html_url}`)
} catch (e) {
  const out = e.stdout ?? ''
  if (out.includes('pull request already exists')) {
    console.log('\nPR already exists, skipping')
  } else {
    throw e
  }
} finally {
  unlinkSync(prPayload)
}
