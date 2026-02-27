/**
 * OpenClaw Skill Loader for Prompt-Bonk
 *
 * Discovers and loads OpenClaw skills that hook into the scanning pipeline
 * BEFORE the security layer (scanner.js) processes incoming text.
 *
 * Skills are loaded from:
 *   1. ./skills/           — Project workspace (OpenClaw convention)
 *   2. ~/.moltbot/skills/  — Global OpenClaw skills
 *
 * Each skill directory must contain a SKILL.md file with YAML frontmatter.
 * Optionally, a hook.js module can export:
 *   - preprocess(text) → string       — transform text before scan
 *   - patterns → Array<PatternDef>    — additional detection patterns
 *   - validateResult(result) → result — post-scan result augmentation
 */

import { readdirSync, readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// SKILL.md frontmatter parser (minimal YAML — no dependency needed)
// ---------------------------------------------------------------------------

function parseFrontmatter(content) {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/);
  if (!match) return { frontmatter: {}, body: content };

  const frontmatter = {};
  for (const line of match[1].split('\n')) {
    const kv = line.match(/^(\w[\w.-]*)\s*:\s*(.+)/);
    if (kv) {
      let val = kv[2].trim();
      // Strip surrounding quotes
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      frontmatter[kv[1]] = val;
    }
  }
  return { frontmatter, body: match[2] };
}

// ---------------------------------------------------------------------------
// Skill discovery
// ---------------------------------------------------------------------------

/**
 * Return the standard OpenClaw skill directories that exist on disk.
 */
export function discoverSkillDirs() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const dirs = [
    join(__dirname, 'skills'),             // Project workspace skills
    join(home, '.moltbot', 'skills'),      // Global OpenClaw skills
  ];
  return dirs.filter(d => {
    try { return existsSync(d); } catch { return false; }
  });
}

// ---------------------------------------------------------------------------
// Skill loading
// ---------------------------------------------------------------------------

/**
 * Discover and load all OpenClaw skills.
 * Returns an array of skill objects with their hooks ready to execute.
 *
 * @param {string[]} [extraDirs] — additional directories to scan
 * @returns {Promise<Array<{name: string, description: string, dir: string, hooks: object}>>}
 */
export async function loadSkills(extraDirs = []) {
  const skills = [];
  const searchDirs = [...discoverSkillDirs(), ...extraDirs];

  for (const dir of searchDirs) {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch { continue; }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const skillDir = join(dir, entry.name);
      const skillMd = join(skillDir, 'SKILL.md');

      if (!existsSync(skillMd)) continue;

      try {
        const content = readFileSync(skillMd, 'utf8');
        const { frontmatter } = parseFrontmatter(content);

        const skill = {
          name: frontmatter.name || entry.name,
          description: frontmatter.description || '',
          dir: skillDir,
          hooks: {},
        };

        // Load hook.js if present — this is the executable skill logic
        // that runs IN FRONT OF the security layer.
        const hookPath = join(skillDir, 'hook.js');
        if (existsSync(hookPath)) {
          const mod = await import(pathToFileURL(hookPath).href);
          if (typeof mod.preprocess === 'function') skill.hooks.preprocess = mod.preprocess;
          if (Array.isArray(mod.patterns)) skill.hooks.patterns = mod.patterns;
          if (typeof mod.validateResult === 'function') skill.hooks.validateResult = mod.validateResult;
        }

        skills.push(skill);
      } catch {
        // Skip malformed skills silently
      }
    }
  }

  return skills;
}

// ---------------------------------------------------------------------------
// Pre-scan middleware (runs BEFORE security layer)
// ---------------------------------------------------------------------------

/**
 * Create a pre-scan middleware pipeline from loaded skills.
 * This middleware intercepts text BEFORE the security scanner processes it.
 *
 * Pipeline order:
 *   1. Skill preprocessors transform text (fetch, normalize, enrich)
 *   2. Scanner.scan() runs security validation (pattern matching + structural)
 *   3. Skill validators optionally augment the result
 *
 * @param {Array} skills — loaded skill objects from loadSkills()
 * @returns {{ preprocess: Function, extraPatterns: Array, postProcess: Function }}
 */
export function createMiddleware(skills) {
  const preprocessors = skills
    .filter(s => s.hooks.preprocess)
    .map(s => ({ name: s.name, fn: s.hooks.preprocess }));

  const extraPatterns = skills
    .filter(s => s.hooks.patterns)
    .flatMap(s => s.hooks.patterns);

  const validators = skills
    .filter(s => s.hooks.validateResult)
    .map(s => ({ name: s.name, fn: s.hooks.validateResult }));

  return {
    /** Number of active skill preprocessors */
    preprocessorCount: preprocessors.length,
    /** Number of extra patterns contributed by skills */
    patternCount: extraPatterns.length,
    /** Extra detection patterns from skills */
    extraPatterns,

    /**
     * Run all skill preprocessors on text.
     * This is the PRE-SECURITY hook — runs before scan().
     * Each preprocessor can transform, fetch, or enrich the text.
     *
     * @param {string} text — raw input text
     * @returns {string} — preprocessed text ready for security scan
     */
    preprocess(text) {
      let result = text;
      for (const { fn } of preprocessors) {
        try {
          const transformed = fn(result);
          if (typeof transformed === 'string') result = transformed;
        } catch {
          // A failing skill preprocessor must never block the security scan
        }
      }
      return result;
    },

    /**
     * Run post-scan validators (optional skill augmentation of results).
     * Runs AFTER the security scan — skills can add metadata but cannot
     * downgrade a security verdict (safe stays safe, blocked stays blocked).
     *
     * @param {object} result — scan result from scanner.js
     * @returns {object} — augmented result
     */
    postProcess(result) {
      let augmented = result;
      for (const { fn } of validators) {
        try {
          const updated = fn(augmented);
          if (updated && typeof updated === 'object') {
            // Skills cannot override the safe/score/verdict — only add metadata
            augmented = {
              ...updated,
              safe: result.safe,
              score: result.score,
              verdict: result.verdict,
            };
          }
        } catch {
          // Failing validator must not affect scan result
        }
      }
      return augmented;
    },
  };
}
