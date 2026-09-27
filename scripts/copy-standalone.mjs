import { cpSync, existsSync, mkdirSync } from 'node:fs'

const staticSource = '.next/static'
const standaloneRoot = '.next/standalone'
const standaloneNext = `${standaloneRoot}/.next`

if (!existsSync(staticSource) || !existsSync(standaloneRoot)) {
  throw new Error('Next.js standalone build output is incomplete')
}

mkdirSync(standaloneNext, { recursive: true })
cpSync(staticSource, `${standaloneNext}/static`, { recursive: true, force: true })
cpSync('public', `${standaloneRoot}/public`, { recursive: true, force: true })
