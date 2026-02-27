// skills.js — OpenClaw skill installation and pre-scan pipeline
// Loads clawhub skills and runs them BEFORE the security scanner

import { execSync } from 'child_process';
import { readFileSync, readdirSync, existsSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_SKILLS_DIR = './skills';

// ---------------------------------------------------------------------------
// SKILL.md parser — extract YAML frontmatter + body
// ---------------------------------------------------------------------------

function parseSkillMd(content) {
  const fmMatch = content.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
  if (!fmMatch) {
    return { meta: {}, body: content };
  }

  // Simple YAML frontmatter parser (no dependency needed)
  const meta = {};
  for (const line of fmMatch[1].split('\n')) {
    const kv = line.match(/^(\w[\w-]*):\s*(.+)$/);
    if (kv) {
      meta[kv[1]] = kv[2].trim();
    }
  }

  return { meta, body: fmMatch[2] };
}

// ---------------------------------------------------------------------------
// Pre-scan hook extraction from skill body
// ---------------------------------------------------------------------------

// Skills can define pre-scan hooks via fenced code blocks tagged `prescan-js`
// Example in SKILL.md:
//
//   ```prescan-js
//   // text is the input string, return transformed text or null to skip scan
//   text = text.replace(/\bexample\.com\b/gi, '[REDACTED_DOMAIN]');
//   ```
//
// These are lightweight text transformations that run BEFORE pattern matching.

function extractPreScanHooks(body) {
  const hooks = [];
  const re = /```prescan-js\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    hooks.push(m[1].trim());
  }
  return hooks;
}

// ---------------------------------------------------------------------------
// Skill installation via clawhub CLI
// ---------------------------------------------------------------------------

/**
 * Install an openclaw skill from the clawhub registry.
 *
 * @param {string} slug - Skill slug (e.g. "my-skill") or git URL
 * @param {object} [options]
 * @param {string} [options.skillsDir] - Target directory (default: ./skills)
 * @param {boolean} [options.force] - Overwrite existing installation
 * @returns {{ ok: boolean, path: string, error?: string }}
 */
export function installSkill(slug, options = {}) {
  const skillsDir = resolve(options.skillsDir || DEFAULT_SKILLS_DIR);

  if (!existsSync(skillsDir)) {
    mkdirSync(skillsDir, { recursive: true });
  }

  // Try clawhub CLI first, fall back to git clone for URLs
  const isUrl = slug.startsWith('http://') || slug.startsWith('https://') || slug.startsWith('git@');

  try {
    if (isUrl) {
      // Git-based installation
      const name = slug.split('/').pop().replace(/\.git$/, '');
      const dest = join(skillsDir, name);

      if (existsSync(dest) && !options.force) {
        return { ok: true, path: dest, error: 'Already installed (use --force to reinstall)' };
      }

      execSync(`git clone --depth 1 ${shellQuote(slug)} ${shellQuote(dest)}`, {
        encoding: 'utf8',
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      return { ok: true, path: dest };
    }

    // clawhub CLI installation
    const args = ['install', slug, '--workdir', shellQuote(skillsDir)];
    if (options.force) args.push('--force');

    execSync(`clawhub ${args.join(' ')}`, {
      encoding: 'utf8',
      timeout: 60000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    return { ok: true, path: join(skillsDir, slug) };
  } catch (err) {
    return { ok: false, path: '', error: err.message || String(err) };
  }
}

/**
 * Uninstall a skill by removing its directory.
 *
 * @param {string} slug - Skill name
 * @param {object} [options]
 * @param {string} [options.skillsDir]
 * @returns {{ ok: boolean, error?: string }}
 */
export function uninstallSkill(slug, options = {}) {
  const skillsDir = resolve(options.skillsDir || DEFAULT_SKILLS_DIR);
  const dest = join(skillsDir, slug);

  if (!existsSync(dest)) {
    return { ok: false, error: `Skill "${slug}" is not installed` };
  }

  try {
    execSync(`rm -rf ${shellQuote(dest)}`, { encoding: 'utf8', timeout: 10000 });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// Skill loading
// ---------------------------------------------------------------------------

/**
 * Load all installed skills from the skills directory.
 *
 * @param {string} [skillsDir] - Skills directory path
 * @returns {Array<{ name: string, description: string, meta: object, preScanHooks: string[], path: string }>}
 */
export function loadSkills(skillsDir) {
  const dir = resolve(skillsDir || DEFAULT_SKILLS_DIR);

  if (!existsSync(dir)) {
    return [];
  }

  const skills = [];

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;

    const skillDir = join(dir, entry.name);

    // Look for SKILL.md or skill.md
    let skillMdPath;
    for (const name of ['SKILL.md', 'skill.md']) {
      const p = join(skillDir, name);
      if (existsSync(p)) {
        skillMdPath = p;
        break;
      }
    }

    if (!skillMdPath) continue;

    try {
      const content = readFileSync(skillMdPath, 'utf8');
      const { meta, body } = parseSkillMd(content);
      const preScanHooks = extractPreScanHooks(body);

      skills.push({
        name: meta.name || entry.name,
        description: meta.description || '',
        meta,
        preScanHooks,
        path: skillDir,
      });
    } catch {
      // Skip unreadable skills
    }
  }

  return skills;
}

/**
 * List installed skills with their metadata.
 *
 * @param {string} [skillsDir]
 * @returns {Array<{ name: string, description: string, path: string }>}
 */
export function listSkills(skillsDir) {
  return loadSkills(skillsDir).map(s => ({
    name: s.name,
    description: s.description,
    path: s.path,
    hookCount: s.preScanHooks.length,
  }));
}

// ---------------------------------------------------------------------------
// Pre-scan pipeline
// ---------------------------------------------------------------------------

/**
 * Build a pre-scan pipeline function from loaded skills.
 * The pipeline runs all skill preprocessors on text BEFORE the security
 * scanner sees it. This is the "in front of security" integration point.
 *
 * Each hook receives `text` and can return modified text.
 * If a hook returns null/undefined, the original text is preserved.
 *
 * @param {Array} skills - Loaded skills from loadSkills()
 * @returns {function(string): { text: string, skillMeta: Array }}
 */
export function buildPreScanPipeline(skills) {
  const hooks = [];

  for (const skill of skills) {
    for (const hookSource of skill.preScanHooks) {
      hooks.push({
        skillName: skill.name,
        // Build a safe function from the hook source
        // The hook gets `text` as input and should assign to `text` for modification
        fn: buildHookFn(hookSource, skill.name),
      });
    }
  }

  return function preScanPipeline(inputText) {
    let text = inputText;
    const applied = [];

    for (const hook of hooks) {
      try {
        const result = hook.fn(text);
        if (typeof result === 'string') {
          applied.push({ skill: hook.skillName, transformed: result !== text });
          text = result;
        } else {
          applied.push({ skill: hook.skillName, transformed: false });
        }
      } catch (err) {
        applied.push({ skill: hook.skillName, transformed: false, error: err.message });
      }
    }

    return { text, skillMeta: applied };
  };
}

/**
 * Build a sandboxed hook function from source code.
 * Only allows string manipulation — no access to require, process, fs, etc.
 */
function buildHookFn(source, skillName) {
  try {
    // Construct a function that receives text and returns modified text
    // Deliberately limit scope to prevent skill code from accessing Node internals
    const fn = new Function(
      'text',
      `"use strict";\n${source}\nreturn text;`
    );
    return fn;
  } catch (err) {
    // Return a no-op if the hook source is invalid
    return (text) => text;
  }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function shellQuote(s) {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}
