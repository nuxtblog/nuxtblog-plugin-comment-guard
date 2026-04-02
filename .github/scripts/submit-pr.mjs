#!/usr/bin/env node
/**
 * Submit PR script — opens a PR to nuxtblog/registry to add or update this plugin.
 * Creates/updates a single file under plugins/ instead of modifying registry.json,
 * so concurrent PRs from different plugins never conflict.
 *
 * Requirements:
 *   - GitHub CLI installed and authenticated: https://cli.github.com
 *   - Plugin repo must be pushed to GitHub
 *   - REGISTRY_PAT secret set (repo scope, for cross-repo PR)
 *
 * Usage:
 *   node .github/scripts/submit-pr.mjs
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

// ── Read local metadata ───────────────────────────────────────────────────────

const pkg = JSON.parse(readFileSync('package.json', 'utf-8'))

const authorName = typeof pkg.author === 'string'
  ? pkg.author
  : (pkg.author?.name ?? '')

function inferType(pluginManifest) {
  if (pluginManifest?.pipelines?.length) return 'pipeline'
  if (pluginManifest?.webhooks?.length)  return 'webhook'
  return 'hook'
}

const plugin = {
  name:        pkg.name,
  title:       pkg.plugin?.title,
  description: pkg.description,
  version:     pkg.version,
  author:      authorName,
  icon:        pkg.plugin?.icon,
  type:        inferType(pkg.plugin),
  keywords:    pkg.keywords ?? [],
  homepage:    pkg.homepage,
  license:     pkg.license,
}

// Derive GitHub repo path from git remote
const remoteUrl = run('git remote get-url origin')
const repoMatch = remoteUrl.match(/[:/]([\w.-]+\/[\w.-]+?)(?:\.git)?$/)
if (!repoMatch) {
  console.error('Cannot parse git remote URL:', remoteUrl)
  process.exit(1)
}
const pluginRepo  = repoMatch[1]                  // e.g. "nuxtblog/nuxtblog-plugin-pinyin-slug"
const pluginOwner = pluginRepo.split('/')[0]

// Derive the file path inside registry:
//   name "owner/slug"  → plugins/owner_slug.json
//   name "slug"        → plugins/{repoOwner}_slug.json
const fileBaseName = plugin.name.includes('/')
  ? plugin.name.replace('/', '_')
  : `${pluginOwner}_${plugin.name}`
const pluginFilePath = `plugins/${fileBaseName}.json`

// ── Get GitHub username ───────────────────────────────────────────────────────

let username
try {
  username = run('gh api user --jq .login')
} catch {
  console.error('GitHub CLI not authenticated. Run: gh auth login')
  process.exit(1)
}

console.log(`\nPlugin : ${plugin.name} v${plugin.version}`)
console.log(`Repo   : ${pluginRepo}`)
console.log(`File   : ${pluginFilePath}`)
console.log(`User   : ${username}`)
console.log(`Target : ${REGISTRY_REPO}\n`)

// ── Fork registry if needed ───────────────────────────────────────────────────

console.log('Ensuring fork exists...')
runSilent(`gh repo fork ${REGISTRY_REPO} --clone=false`)

console.log('Syncing fork with upstream...')
runSilent(`gh repo sync ${username}/registry`)

// ── Check if entry already exists in registry ─────────────────────────────────

let existingEntry = null

const existingRaw = runSilent(`gh api "repos/${REGISTRY_REPO}/contents/${pluginFilePath}"`)
if (existingRaw) {
  try {
    const fileInfo = JSON.parse(existingRaw)
    existingEntry = JSON.parse(Buffer.from(fileInfo.content, 'base64').toString())
  } catch {}
}

// ── Validate ──────────────────────────────────────────────────────────────────

// Name must not be taken by a different repo
if (existingEntry && existingEntry.repo !== pluginRepo) {
  console.error(`\n❌ Name conflict: "${plugin.name}" is already registered by ${existingEntry.repo}`)
  console.error('   Choose a different name in package.json and try again.')
  process.exit(1)
}

// Version must not go backwards
if (existingEntry) {
  const semver = v => v.replace(/^v/, '').split('.').map(Number)
  const [eMaj, eMin, ePat] = semver(existingEntry.version)
  const [nMaj, nMin, nPat] = semver(plugin.version)
  const isNewer =
    nMaj > eMaj ||
    (nMaj === eMaj && nMin > eMin) ||
    (nMaj === eMaj && nMin === eMin && nPat > ePat)
  if (!isNewer) {
    console.error(`\n❌ Version regression: registry has v${existingEntry.version}, cannot publish v${plugin.version}`)
    console.error('   Bump the version in package.json and push a new tag.')
    process.exit(1)
  }
}

// ── Build entry ───────────────────────────────────────────────────────────────

const now = new Date().toISOString()
const entry = {
  name:         plugin.name,
  title:        plugin.title,
  description:  plugin.description,
  version:      plugin.version,
  author:       plugin.author || username,
  icon:         plugin.icon  || 'i-tabler-plug',
  repo:         pluginRepo,
  homepage:     plugin.homepage || `https://github.com/${pluginRepo}`,
  tags:         plugin.keywords.filter(k => k !== 'nuxtblog-plugin'),
  type:         plugin.type,
  is_official:  existingEntry?.is_official ?? false,
  license:      plugin.license || 'MIT',
  published_at: existingEntry?.published_at ?? now,
  updated_at:   now,
}

console.log(existingEntry ? `Updating entry: ${plugin.name}` : `Adding new entry: ${plugin.name}`)

// ── Create branch in fork ─────────────────────────────────────────────────────

const branch = `plugin/${plugin.name.replace(/\//g, '-')}-v${plugin.version}`
const defaultBranch = run(`gh api repos/${username}/registry --jq .default_branch`).replace(/^"|"$/g, '')
const branchSha = JSON.parse(
  run(`gh api repos/${username}/registry/branches/${defaultBranch}`)
).commit.sha

runSilent(
  `gh api repos/${username}/registry/git/refs --method POST -f ref=refs/heads/${branch} -f sha=${branchSha}`
)
console.log(`Branch: ${branch}`)

// ── Commit the single plugin file to fork branch ──────────────────────────────

// SHA required for update (PUT), not needed for create
let forkFileSha = null
const forkFileRaw = runSilent(`gh api "repos/${username}/registry/contents/${pluginFilePath}?ref=${branch}"`)
if (forkFileRaw) {
  try { forkFileSha = JSON.parse(forkFileRaw).sha } catch {}
}

const newContent = Buffer.from(JSON.stringify(entry, null, 2) + '\n').toString('base64')
const commitMsg  = existingEntry
  ? `chore: update ${plugin.name} to v${plugin.version}`
  : `feat: add ${plugin.name} v${plugin.version}`

const tmpFile = join(tmpdir(), 'plugin-entry-payload.json')
const payload = { message: commitMsg, content: newContent, branch }
if (forkFileSha) payload.sha = forkFileSha

writeFileSync(tmpFile, JSON.stringify(payload))
run(`gh api repos/${username}/registry/contents/${pluginFilePath} --method PUT --input "${tmpFile}"`)
unlinkSync(tmpFile)
console.log(`Committed ${pluginFilePath} to fork`)

// ── Open PR ───────────────────────────────────────────────────────────────────

const prTitle = existingEntry
  ? `chore: update plugin ${plugin.name} to v${plugin.version}`
  : `feat: add plugin ${plugin.name} v${plugin.version}`

const prBody = [
  '## Plugin Submission',
  '',
  '| Field | Value |',
  '|---|---|',
  `| Name | \`${plugin.name}\` |`,
  `| Version | \`${plugin.version}\` |`,
  `| Type | \`${entry.type}\` |`,
  `| Repo | [\`${pluginRepo}\`](https://github.com/${pluginRepo}) |`,
  '',
  plugin.description,
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
