#!/usr/bin/env node

import { scan, isInjection } from './scanner.js';
import { loadSkills, createMiddleware } from './skill-loader.js';
import { readFileSync } from 'fs';
import { execSync } from 'child_process';

// ---------------------------------------------------------------------------
// CLI — scan text from stdin, file, or argument
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
  } else if (args[i] === '--install-skill') {
    flags.installSkill = args[++i];
  } else if (args[i] === '--list-skills') {
    flags.listSkills = true;
  } else if (args[i] === '--no-skills') {
    flags.noSkills = true;
  } else if (args[i] === '--help' || args[i] === '-h') {
    console.log(`prompt-bonk — Scan text for prompt injection attempts

Usage:
  echo "text" | prompt-bonk [options]
  prompt-bonk --file input.txt [options]
  prompt-bonk "text to scan" [options]

Options:
  --threshold, -t <n>  Score threshold (0-1, default: 0.50)
  --fast, -f           Stop at first high-confidence match
  --json, -j           Output full JSON result
  --quiet, -q          Exit code only (0=safe, 1=injection)
  --file <path>        Read text from file
  --no-skills          Disable skill loading
  --help, -h           Show this help

Skill management:
  --install-skill <source>  Install an OpenClaw skill (GitHub shorthand, URL, or local path)
  --list-skills             List installed OpenClaw skills

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
// Skill management commands
// ---------------------------------------------------------------------------

if (flags.installSkill) {
  try {
    console.log(`Installing OpenClaw skill: ${flags.installSkill}`);
    execSync(`npx skills add ${flags.installSkill} -a openclaw -y`, { stdio: 'inherit' });
    console.log('Skill installed successfully.');
  } catch (err) {
    console.error(`Failed to install skill: ${err.message}`);
    process.exit(2);
  }
  process.exit(0);
}

if (flags.listSkills) {
  try {
    const skills = await loadSkills();
    if (skills.length === 0) {
      console.log('No OpenClaw skills installed.');
      console.log('Install skills with: prompt-bonk --install-skill <source>');
    } else {
      console.log(`Installed skills (${skills.length}):\n`);
      for (const s of skills) {
        const hooks = [];
        if (s.hooks.preprocess) hooks.push('preprocess');
        if (s.hooks.patterns) hooks.push(`patterns(${s.hooks.patterns.length})`);
        if (s.hooks.validateResult) hooks.push('validateResult');
        const hookStr = hooks.length > 0 ? ` [${hooks.join(', ')}]` : '';
        console.log(`  ${s.name} — ${s.description}${hookStr}`);
        console.log(`    ${s.dir}`);
      }
    }
  } catch (err) {
    console.error(`Error listing skills: ${err.message}`);
    process.exit(2);
  }
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Input handling
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

// ---------------------------------------------------------------------------
// Scan with skill middleware
// ---------------------------------------------------------------------------

try {
  const text = await getText();

  // Load OpenClaw skills — these run IN FRONT OF the security layer
  let middleware = null;
  if (!flags.noSkills) {
    try {
      const skills = await loadSkills();
      if (skills.length > 0) {
        middleware = createMiddleware(skills);
      }
    } catch {
      // Skill loading failure must never block security scanning
    }
  }

  // PRE-SECURITY: Run skill preprocessors before scan
  const processedText = middleware ? middleware.preprocess(text) : text;

  // SECURITY LAYER: Run the scanner
  const result = scan(processedText, {
    threshold: flags.threshold,
    fast: flags.fast,
  });

  // POST-SECURITY: Run skill validators (cannot downgrade verdicts)
  const finalResult = middleware ? middleware.postProcess(result) : result;

  if (flags.quiet) {
    process.exit(finalResult.safe ? 0 : 1);
  }

  if (flags.json) {
    console.log(JSON.stringify(finalResult, null, 2));
  } else {
    // Human-readable output
    const icon = finalResult.safe ? 'SAFE' : 'BLOCKED';
    const scoreBar = '|' + '#'.repeat(Math.round(finalResult.score * 20)) + '.'.repeat(20 - Math.round(finalResult.score * 20)) + '|';

    console.log(`\n  ${icon}  score=${finalResult.score}  verdict=${finalResult.verdict}`);
    console.log(`  ${scoreBar}`);

    if (finalResult.matches.length > 0) {
      console.log(`\n  Matches (${finalResult.matches.length}):`);
      for (const m of finalResult.matches.slice(0, 10)) {
        console.log(`    [${m.weight.toFixed(2)}] ${m.category}/${m.id}: ${m.description}`);
        console.log(`           "${m.matched.slice(0, 80)}"`);
      }
    }

    if (finalResult.structural.signals.length > 0) {
      console.log(`\n  Structural signals:`);
      for (const s of finalResult.structural.signals) {
        console.log(`    [${s.score.toFixed(2)}] ${s.id}: ${s.detail}`);
      }
    }

    if (middleware && (middleware.preprocessorCount > 0 || middleware.patternCount > 0)) {
      console.log(`\n  Skills: ${middleware.preprocessorCount} preprocessor(s), ${middleware.patternCount} extra pattern(s)`);
    }

    console.log();
  }

  process.exit(finalResult.safe ? 0 : 1);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(2);
}
