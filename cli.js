#!/usr/bin/env node

import { scan as _baseScan, createPipeline } from './scanner.js';
import { readFileSync } from 'fs';
import { installSkill, uninstallSkill, listSkills, loadSkills, buildPreScanPipeline } from './skills.js';

// ---------------------------------------------------------------------------
// CLI — scan text from stdin, file, or argument
//        + openclaw skill management
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const flags = {};
const positional = [];

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--threshold' || args[i] === '-t') {
    flags.threshold = parseFloat(args[++i]);
  } else if (args[i] === '--fast' || args[i] === '-f') {
    flags.fast = true;
  } else if (args[i] === '--json' || args[i] === '-j') {
    flags.json = true;
  } else if (args[i] === '--quiet' || args[i] === '-q') {
    flags.quiet = true;
  } else if (args[i] === '--file') {
    flags.file = args[++i];
  } else if (args[i] === '--skills-dir') {
    flags.skillsDir = args[++i];
  } else if (args[i] === '--no-skills') {
    flags.noSkills = true;
  } else if (args[i] === '--help' || args[i] === '-h') {
    console.log(`prompt-bonk — Scan text for prompt injection attempts

Usage:
  echo "text" | prompt-bonk [options]
  prompt-bonk --file input.txt [options]
  prompt-bonk "text to scan" [options]

Scan Options:
  --threshold, -t <n>  Score threshold (0-1, default: 0.50)
  --fast, -f           Stop at first high-confidence match
  --json, -j           Output full JSON result
  --quiet, -q          Exit code only (0=safe, 1=injection)
  --file <path>        Read text from file
  --skills-dir <path>  Skills directory (default: ./skills)
  --no-skills          Disable skill pipeline

Skill Management:
  prompt-bonk skill install <slug|url>   Install an openclaw skill
  prompt-bonk skill uninstall <slug>     Remove a skill
  prompt-bonk skill list                 List installed skills

Exit codes:
  0  Text appears safe
  1  Prompt injection detected
  2  Error`);
    process.exit(0);
  } else if (!args[i].startsWith('-')) {
    positional.push(args[i]);
  }
}

// ---------------------------------------------------------------------------
// Skill subcommands
// ---------------------------------------------------------------------------

if (positional[0] === 'skill') {
  const subcmd = positional[1];
  const skillsDir = flags.skillsDir;

  if (subcmd === 'install') {
    const slug = positional[2];
    if (!slug) {
      console.error('Error: skill install requires a slug or URL');
      process.exit(2);
    }
    const result = installSkill(slug, { skillsDir, force: flags.fast });
    if (result.ok) {
      console.log(`Installed: ${slug} -> ${result.path}`);
      if (result.error) console.log(`  Note: ${result.error}`);
    } else {
      console.error(`Failed to install "${slug}": ${result.error}`);
      process.exit(2);
    }
    process.exit(0);
  }

  if (subcmd === 'uninstall' || subcmd === 'remove') {
    const slug = positional[2];
    if (!slug) {
      console.error('Error: skill uninstall requires a slug');
      process.exit(2);
    }
    const result = uninstallSkill(slug, { skillsDir });
    if (result.ok) {
      console.log(`Uninstalled: ${slug}`);
    } else {
      console.error(`Failed: ${result.error}`);
      process.exit(2);
    }
    process.exit(0);
  }

  if (subcmd === 'list' || subcmd === 'ls') {
    const skills = listSkills(skillsDir);
    if (skills.length === 0) {
      console.log('No skills installed.');
    } else {
      if (flags.json) {
        console.log(JSON.stringify(skills, null, 2));
      } else {
        console.log(`\n  Installed skills (${skills.length}):\n`);
        for (const s of skills) {
          console.log(`    ${s.name} — ${s.description || '(no description)'}`);
          console.log(`      path: ${s.path}  hooks: ${s.hookCount}`);
        }
        console.log();
      }
    }
    process.exit(0);
  }

  console.error(`Unknown skill command: ${subcmd}\nUse: skill install|uninstall|list`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Build scan function (with or without skill pipeline)
// ---------------------------------------------------------------------------

let scan = _baseScan;

if (!flags.noSkills) {
  const skills = loadSkills(flags.skillsDir);
  if (skills.length > 0) {
    const pipeline = buildPreScanPipeline(skills);
    const pipelined = createPipeline(pipeline);
    scan = pipelined.scan;
  }
}

// ---------------------------------------------------------------------------
// Scan mode
// ---------------------------------------------------------------------------

async function getText() {
  if (flags.file) {
    return readFileSync(flags.file, 'utf8');
  }
  if (positional.length > 0) {
    return positional.join(' ');
  }
  // Read from stdin
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
    // Timeout after 5 seconds if no input
    setTimeout(() => {
      if (!data) {
        reject(new Error('No input received (timeout after 5s). Provide text via stdin, --file, or as argument.'));
      }
    }, 5000);
  });
}

try {
  const text = await getText();
  const result = scan(text, {
    threshold: flags.threshold,
    fast: flags.fast,
  });

  if (flags.quiet) {
    process.exit(result.safe ? 0 : 1);
  }

  if (flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    // Human-readable output
    const icon = result.safe ? 'SAFE' : 'BLOCKED';
    const scoreBar = '|' + '#'.repeat(Math.round(result.score * 20)) + '.'.repeat(20 - Math.round(result.score * 20)) + '|';

    console.log(`\n  ${icon}  score=${result.score}  verdict=${result.verdict}`);
    console.log(`  ${scoreBar}`);

    if (result.matches.length > 0) {
      console.log(`\n  Matches (${result.matches.length}):`);
      for (const m of result.matches.slice(0, 10)) {
        console.log(`    [${m.weight.toFixed(2)}] ${m.category}/${m.id}: ${m.description}`);
        console.log(`           "${m.matched.slice(0, 80)}"`);
      }
    }

    if (result.structural.signals.length > 0) {
      console.log(`\n  Structural signals:`);
      for (const s of result.structural.signals) {
        console.log(`    [${s.score.toFixed(2)}] ${s.id}: ${s.detail}`);
      }
    }

    // Show skill pipeline info if skills were active
    if (result.skills && result.skills.length > 0) {
      console.log(`\n  Skills pipeline:`);
      for (const s of result.skills) {
        const status = s.error ? `error: ${s.error}` : s.transformed ? 'transformed' : 'pass-through';
        console.log(`    ${s.skill}: ${status}`);
      }
    }

    console.log();
  }

  process.exit(result.safe ? 0 : 1);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(2);
}
