// Copy GenosDB's self-contained dist/ into public/genosdb so Vite serves it
// intact (a single folder) in both dev and build. GenosDB resolves its own
// modules at runtime via new URL('./*.min.js', import.meta.url), so they must
// all live together and never be bundled/split. Runs before `vite` / `vite build`.
import { rm, mkdir, readdir, copyFile, access } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const src = join(root, 'node_modules', 'genosdb', 'dist')
const out = join(root, 'public', 'genosdb')

try {
  await access(src)
} catch {
  console.error('[genosdb] node_modules/genosdb/dist not found — run `pnpm install` first.')
  process.exit(1)
}

await rm(out, { recursive: true, force: true })
await mkdir(out, { recursive: true })
const files = (await readdir(src)).filter((f) => f.endsWith('.js'))
await Promise.all(files.map((f) => copyFile(join(src, f), join(out, f))))
console.log(`[genosdb] copied ${files.length} module files -> public/genosdb`)
