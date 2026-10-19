#!/usr/bin/env node

/**
 * check-supply-chain.js
 *
 * Blocks the "disguised payload + editor auto-run" supply-chain pattern that
 * hit this repository (see SECURITY.md, "Repository supply-chain safeguards").
 *
 * The attack chain was:
 *
 *   1. An obfuscated Node script was committed as `public/fonts/fa-solid-600.eot`
 *      so it read as a font in review — Font Awesome ships weights 400/900/300,
 *      never 600, and the bytes were ASCII JavaScript rather than EOT.
 *   2. A hidden `.vscode/tasks.json` task ran `node ./public/fonts/fa-solid-600.eot`
 *      with `"runOn": "folderOpen"`.
 *   3. `"task.allowAutomaticTasks": true` in `.vscode/settings.json` removed the
 *      confirmation prompt, so merely opening the folder executed the payload.
 *
 * Each rule below breaks one link in that chain, by shape rather than by
 * filename, so a renamed variant is still caught:
 *
 *   1. DISGUISED_EXECUTABLE  — media/binary-extension files holding script text.
 *   2. EDITOR_AUTO_RUN       — tasks that run on folder open, or auto-run enabled.
 *   3. INSTALL_LIFECYCLE     — npm install-time hooks outside the allowlist.
 *   4. INTERPRETER_ON_ASSET  — any command feeding a media file to an interpreter.
 *
 * A cross-format mismatch between two genuine media formats (a PNG named .ico,
 * for example) is reported as a notice, not a failure: it is common and
 * harmless, and failing on it would train people to ignore this check.
 *
 * Usage:
 *   node scripts/check-supply-chain.js [--root <dir>] [--quiet]
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// ── Configuration ──────────────────────────────────────────────────────────

// Extensions that must never contain executable script text.
const ASSET_EXTENSIONS = new Set([
  '.woff',
  '.woff2',
  '.eot',
  '.ttf',
  '.otf',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.ico',
  '.bmp',
  '.webp',
  '.avif',
  '.mp3',
  '.mp4',
  '.wav',
  '.ogg',
  '.webm',
  '.pdf',
  '.bin',
  '.dat',
  '.llf',
  '.wasm',
  '.node',
  // SVG is text by design, so it needs the `svg` signature below to be
  // recognised as a genuine asset. It is included because an SVG can carry a
  // <script> element, though a reviewer at least sees it in the diff.
  '.svg',
]);

// Install-time npm hooks. `prepare` is included because pnpm/npm run it on
// every `install`, which is exactly what makes it attractive to an attacker.
const LIFECYCLE_HOOKS = [
  'preinstall',
  'install',
  'postinstall',
  'preprepare',
  'prepare',
  'postprepare',
  'prepublish',
  'prepublishOnly',
  'prepack',
  'postpack',
];

// Reviewed, intentional lifecycle hooks: "<package.json path>:<hook>" -> command.
// Adding an entry here is a deliberate decision and a CODEOWNERS-reviewed change.
const ALLOWED_LIFECYCLE = {
  'package.json:prepare': 'husky',
};

// Editor/container keys that cause code to run without an explicit user action.
const AUTO_RUN_CONFIG_GLOBS = [/^\.vscode\//, /^\.devcontainer\//];

const DEVCONTAINER_LIFECYCLE = [
  'initializeCommand',
  'onCreateCommand',
  'updateContentCommand',
  'postCreateCommand',
  'postStartCommand',
  'postAttachCommand',
];

// Interpreters that would execute a file handed to them as an argument.
const INTERPRETERS = [
  'node',
  'nodejs',
  'deno',
  'bun',
  'python',
  'python3',
  'ruby',
  'perl',
  'sh',
  'bash',
  'zsh',
];

// Magic-byte signatures for formats we can positively identify.
const SIGNATURES = [
  { format: 'woff', test: (b) => b.slice(0, 4).toString('latin1') === 'wOFF' },
  { format: 'woff2', test: (b) => b.slice(0, 4).toString('latin1') === 'wOF2' },
  { format: 'otf', test: (b) => b.slice(0, 4).toString('latin1') === 'OTTO' },
  {
    format: 'ttf',
    test: (b) =>
      b.slice(0, 4).equals(Buffer.from([0x00, 0x01, 0x00, 0x00])) ||
      ['true', 'ttcf'].includes(b.slice(0, 4).toString('latin1')),
  },
  // EOT has no magic at offset 0; its 0x504C marker sits at byte 34.
  { format: 'eot', test: (b) => b.length > 35 && b[34] === 0x4c && b[35] === 0x50 },
  {
    format: 'png',
    test: (b) =>
      b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  },
  { format: 'jpeg', test: (b) => b.slice(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff])) },
  { format: 'gif', test: (b) => b.slice(0, 4).toString('latin1') === 'GIF8' },
  { format: 'ico', test: (b) => b.slice(0, 4).equals(Buffer.from([0x00, 0x00, 0x01, 0x00])) },
  { format: 'bmp', test: (b) => b.slice(0, 2).toString('latin1') === 'BM' },
  {
    format: 'webp',
    test: (b) =>
      b.slice(0, 4).toString('latin1') === 'RIFF' && b.slice(8, 12).toString('latin1') === 'WEBP',
  },
  { format: 'riff', test: (b) => b.slice(0, 4).toString('latin1') === 'RIFF' },
  { format: 'mp4', test: (b) => b.slice(4, 8).toString('latin1') === 'ftyp' },
  { format: 'pdf', test: (b) => b.slice(0, 5).toString('latin1') === '%PDF-' },
  { format: 'wasm', test: (b) => b.slice(0, 4).equals(Buffer.from([0x00, 0x61, 0x73, 0x6d])) },
  // Text-based, so matched by content: an XML prologue and/or an <svg> root.
  { format: 'svg', test: (b) => /<svg[\s>]/i.test(b.slice(0, 4096).toString('utf-8')) },
  { format: 'elf', test: (b) => b.slice(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) },
  { format: 'mp3', test: (b) => b.slice(0, 3).toString('latin1') === 'ID3' },
  { format: 'avif-or-heif', test: (b) => b.slice(4, 8).toString('latin1') === 'ftyp' },
  { format: 'gzip', test: (b) => b[0] === 0x1f && b[1] === 0x8b },
  { format: 'zip-or-ooxml', test: (b) => b.slice(0, 2).toString('latin1') === 'PK' },
];

// Script carriers specific to SVG, which is markup and so needs its own set.
const SVG_SCRIPT_MARKERS = [
  /<script[\s>]/i,
  /javascript:/i,
  /\bon(load|error|click|mouseover)\s*=/i,
];

// Markers that indicate a text blob is executable code rather than data.
const SCRIPT_MARKERS = [
  /\brequire\s*\(/,
  /\bprocess\s*\.\s*env\b/,
  /\bchild_process\b/,
  /\bspawn(Sync)?\s*\(/,
  /\bexec(Sync|File)?\s*\(/,
  /\beval\s*\(/,
  /\bnew\s+Function\s*\(/,
  /\bFunction\s*\(\s*['"`]/,
  /\bglobalThis\b/,
  /\bmodule\s*\.\s*exports\b/,
  /\bimport\s*\(/,
  /^\s*#!/,
  /\bBuffer\s*\.\s*from\s*\(/,
  /\batob\s*\(/,
  /\bXMLHttpRequest\b/,
  /\bfetch\s*\(/,
];

// ── Helpers ────────────────────────────────────────────────────────────────

/** Lists tracked files, falling back to a filesystem walk outside a git repo. */
function listFiles(root) {
  try {
    const out = execFileSync('git', ['-C', root, 'ls-files', '-z'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 64 * 1024 * 1024,
    });
    const files = out.split('\0').filter(Boolean);
    if (files.length > 0) return files;
  } catch {
    // Not a git repo (or git unavailable) — walk instead.
  }

  const results = [];
  const skipDirs = new Set([
    '.git',
    'node_modules',
    'dist',
    'build',
    'coverage',
    '.turbo',
    '.next',
  ]);
  (function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) walk(abs);
      } else if (entry.isFile()) {
        results.push(path.relative(root, abs).split(path.sep).join('/'));
      }
    }
  })(root);
  return results;
}

/** True when a buffer looks like text: no NUL bytes and mostly printable. */
function looksLikeText(buf) {
  if (buf.length === 0) return false;
  if (buf.includes(0x00)) return false;
  let printable = 0;
  for (const byte of buf) {
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte <= 0x7e))
      printable++;
  }
  return printable / buf.length > 0.9;
}

/** Identifies a buffer against the known signature list. */
function identify(buf) {
  for (const sig of SIGNATURES) {
    try {
      if (sig.test(buf)) return sig.format;
    } catch {
      // A buffer too short for this signature simply does not match.
    }
  }
  return null;
}

/** Maps an extension to the signature formats that legitimately satisfy it. */
function expectedFormats(ext) {
  switch (ext) {
    case '.jpg':
    case '.jpeg':
      return ['jpeg'];
    case '.wav':
    case '.ogg':
    case '.webm':
      return ['riff', 'webp', 'mp4'];
    case '.avif':
      return ['avif-or-heif', 'mp4'];
    case '.mp4':
      return ['mp4', 'avif-or-heif'];
    case '.node':
      return ['elf', 'zip-or-ooxml'];
    case '.bin':
    case '.dat':
    case '.llf':
      return null; // Opaque container: no signature to expect.
    default:
      return [ext.slice(1)];
  }
}

function readPrefix(absPath, bytes) {
  const fd = fs.openSync(absPath, 'r');
  try {
    const buf = Buffer.alloc(bytes);
    const read = fs.readSync(fd, buf, 0, bytes, 0);
    return buf.subarray(0, read);
  } finally {
    fs.closeSync(fd);
  }
}

// ── Rule 1: executable content hiding behind a media extension ─────────────

function checkDisguisedExecutables(root, files, errors, notices) {
  for (const rel of files) {
    const ext = path.extname(rel).toLowerCase();
    if (!ASSET_EXTENSIONS.has(ext)) continue;

    const abs = path.join(root, rel);
    let stat;
    try {
      stat = fs.statSync(abs);
    } catch {
      continue; // Staged deletion or broken symlink.
    }
    if (!stat.isFile() || stat.size === 0) continue;

    const prefix = readPrefix(abs, Math.min(stat.size, 8192));
    const detected = identify(prefix);

    if (looksLikeText(prefix)) {
      const text = prefix.toString('utf-8');
      // An SVG is legitimately text and legitimately full of markup, so the
      // general code markers would fire on harmless files. Only an actual
      // script element or javascript: URL is a finding here.
      const markers = ext === '.svg' ? SVG_SCRIPT_MARKERS : SCRIPT_MARKERS;
      const hits = markers.filter((re) => re.test(text)).map((re) => String(re));
      if (hits.length > 0) {
        errors.push(
          `${rel}: declared as "${ext}" but contains executable script text ` +
            `(${hits.length} code marker(s), e.g. ${hits[0]}). ` +
            `A real asset never contains code — treat this file as malware and do not run it.`,
        );
        continue;
      }
      if (!detected) {
        errors.push(
          `${rel}: declared as "${ext}" but the contents are plain text, not a binary asset. ` +
            `Verify what this file really is before committing it.`,
        );
        continue;
      }
    }

    const expected = expectedFormats(ext);
    if (expected && detected && !expected.includes(detected)) {
      notices.push(
        `${rel}: contains ${detected.toUpperCase()} data though named "${ext}" (benign format mismatch, not a security finding).`,
      );
    } else if (expected && !detected) {
      notices.push(`${rel}: unrecognised binary format for "${ext}" — worth a human look.`);
    }
  }
}

// ── Rule 2: editor / devcontainer configuration that runs code on open ─────

function checkEditorAutoRun(root, files, errors) {
  for (const rel of files) {
    if (!AUTO_RUN_CONFIG_GLOBS.some((re) => re.test(rel))) continue;
    if (!/\.(json|jsonc|ya?ml)$/i.test(rel)) continue;

    const abs = path.join(root, rel);
    let raw;
    try {
      raw = fs.readFileSync(abs, 'utf-8');
    } catch {
      continue;
    }

    if (/["']?runOn["']?\s*:\s*["']folderOpen["']/.test(raw)) {
      errors.push(
        `${rel}: declares a task with "runOn": "folderOpen". ` +
          `Such a task executes as soon as the folder is opened. Remove it, or run the task manually.`,
      );
    }

    const autoTasks = raw.match(/["']task\.allowAutomaticTasks["']\s*:\s*(true|["'][a-z]+["'])/i);
    if (autoTasks && !/["']off["']/i.test(autoTasks[1])) {
      errors.push(
        `${rel}: sets task.allowAutomaticTasks to ${autoTasks[1]}. ` +
          `This removes the confirmation prompt before automatic tasks run. It must stay "off".`,
      );
    }

    if (rel.startsWith('.devcontainer/')) {
      for (const hook of DEVCONTAINER_LIFECYCLE) {
        if (new RegExp(`["']${hook}["']\\s*:`).test(raw)) {
          errors.push(
            `${rel}: defines "${hook}", which runs automatically when the container starts. ` +
              `If this is intentional, document it and have a CODEOWNER review it.`,
          );
        }
      }
    }
  }
}

// ── Rule 3: npm install-time lifecycle hooks ───────────────────────────────

function checkInstallLifecycle(root, files, errors, notices) {
  for (const rel of files) {
    if (path.basename(rel) !== 'package.json') continue;
    if (rel.includes('node_modules/')) continue;

    const abs = path.join(root, rel);
    let pkg;
    try {
      pkg = JSON.parse(fs.readFileSync(abs, 'utf-8'));
    } catch (e) {
      // Malformed JSON is a build problem, not a supply-chain finding. Report it
      // so the file is not silently treated as cleared, but let other rules decide
      // the exit code — this check must not double as a JSON linter.
      notices.push(
        `${rel}: could not be parsed, so its lifecycle scripts were not inspected (${e.message}).`,
      );
      continue;
    }
    if (!pkg.scripts || typeof pkg.scripts !== 'object') continue;

    for (const hook of LIFECYCLE_HOOKS) {
      const command = pkg.scripts[hook];
      if (typeof command !== 'string') continue;

      if (ALLOWED_LIFECYCLE[`${rel}:${hook}`] === command.trim()) continue;

      errors.push(
        `${rel}: defines an install-time "${hook}" script (${JSON.stringify(command)}). ` +
          `These run automatically on \`pnpm install\`. Allowlist it in scripts/check-supply-chain.js ` +
          `(ALLOWED_LIFECYCLE) only after a CODEOWNER has reviewed it.`,
      );
    }
  }
}

// ── Rule 4: an interpreter being handed a media file ──────────────────────

function checkInterpreterOnAsset(root, files, errors) {
  const assetExtPattern = [...ASSET_EXTENSIONS].map((e) => e.slice(1)).join('|');
  const pattern = new RegExp(
    `\\b(${INTERPRETERS.join('|')})\\b[^\\n;|&]{0,200}?[\\w./\\\\-]+\\.(${assetExtPattern})\\b`,
    'i',
  );

  for (const rel of files) {
    if (!/\.(json|jsonc|ya?ml|js|cjs|mjs|ts|sh|bash|ps1|cmd|bat|toml|cfg|conf)$/i.test(rel))
      continue;
    if (rel === 'scripts/check-supply-chain.js' || rel === 'scripts/check-supply-chain.spec.ts')
      continue;

    const abs = path.join(root, rel);
    let stat;
    try {
      stat = fs.statSync(abs);
    } catch {
      continue;
    }
    if (!stat.isFile() || stat.size > 2 * 1024 * 1024) continue;

    const raw = fs.readFileSync(abs, 'utf-8');
    for (const line of raw.split('\n')) {
      const match = line.match(pattern);
      if (match) {
        errors.push(
          `${rel}: runs an interpreter against an asset file — "${match[0].trim()}". ` +
            `Media files are data, never programs; this is how a disguised payload gets executed.`,
        );
        break;
      }
    }
  }
}

// ── Entry point ────────────────────────────────────────────────────────────

function run(root) {
  const errors = [];
  const notices = [];
  const files = listFiles(root);

  checkDisguisedExecutables(root, files, errors, notices);
  checkEditorAutoRun(root, files, errors);
  checkInstallLifecycle(root, files, errors, notices);
  checkInterpreterOnAsset(root, files, errors);

  return { errors, notices, scanned: files.length };
}

function main() {
  const argv = process.argv.slice(2);
  const quiet = argv.includes('--quiet');
  const rootFlag = argv.indexOf('--root');
  const root =
    rootFlag !== -1 && argv[rootFlag + 1]
      ? path.resolve(argv[rootFlag + 1])
      : path.resolve(__dirname, '..');

  if (!quiet) console.log(`Checking repository for supply-chain red flags in ${root}...\n`);

  const { errors, notices, scanned } = run(root);

  if (!quiet && notices.length > 0) {
    console.log(`ℹ️  ${notices.length} notice(s):\n`);
    notices.forEach((n) => console.log(`  - ${n}`));
    console.log('');
  }

  if (errors.length > 0) {
    console.error(
      `❌ Found ${errors.length} supply-chain red flag(s) across ${scanned} tracked file(s):\n`,
    );
    errors.forEach((err) => console.error(`  - ${err}`));
    console.error(
      "\nThese patterns execute code on contributors' machines without consent.\n" +
        'See SECURITY.md ("Repository supply-chain safeguards") before overriding this check.\n',
    );
    process.exit(1);
  }

  if (!quiet)
    console.log(`✓ No supply-chain red flags found (${scanned} tracked files scanned).\n`);
  process.exit(0);
}

if (require.main === module) main();

module.exports = { run, looksLikeText, identify, SCRIPT_MARKERS, ALLOWED_LIFECYCLE };
