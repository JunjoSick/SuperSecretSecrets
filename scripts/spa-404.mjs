// Copies dist/index.html to dist/404.html so that GitHub Pages serves the SPA
// shell for deep links (/encode, /recover, /about) instead of a 404 page.
// Also writes a .nojekyll file so GH Pages does not run Jekyll on our output.
import { copyFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const indexPath = resolve(root, 'dist', 'index.html');
const fallbackPath = resolve(root, 'dist', '404.html');
const nojekyllPath = resolve(root, 'dist', '.nojekyll');

if (!existsSync(indexPath)) {
  console.error(`[spa-404] skipped: ${indexPath} does not exist.`);
  process.exit(0);
}

copyFileSync(indexPath, fallbackPath);
writeFileSync(nojekyllPath, '');
console.log('[spa-404] wrote dist/404.html and dist/.nojekyll');
