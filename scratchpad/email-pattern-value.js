import { scan, PATTERNS } from '../scanner.js';
import fs from 'fs';
import path from 'path';

// Check which datasets benefit from these patterns
console.log('=== EMAIL PATTERN VALUE ACROSS DATASETS ===\n');

const datasets = [
  'datasets/injecagent.jsonl',
  'datasets/protectai.jsonl',
  'datasets/jailbreak-prompts.jsonl',
  'datasets/safeguard-test.jsonl'
];

const emailPatternIds = ['send_it_to_email', 'send_to_specific_email', 'data_to_personal_email', 'forward_to_email'];

for (const dsPath of datasets) {
  const fullPath = path.join('/ml2/nanobot/projects/prompt-guard-ats', dsPath);
  if (!fs.existsSync(fullPath)) {
    console.log(`${path.basename(dsPath)}: NOT FOUND\n`);
    continue;
  }

  const rows = fs.readFileSync(fullPath, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  const emailPatternMatches = {};
  let emailPatternTruePositives = 0;
  let totalActualPositives = 0;

  for (const row of rows) {
    // Handle different label formats
    const isInjection = row.is_injection === true || row.label === 1 || row.label === 'injection';
    if (isInjection) totalActualPositives++;

    const res = scan(row.text);
    const emailMatches = res.matches.filter(m => emailPatternIds.includes(m.id));

    if (emailMatches.length > 0) {
      for (const m of emailMatches) {
        emailPatternMatches[m.id] = (emailPatternMatches[m.id] || 0) + 1;
        if (isInjection) emailPatternTruePositives++;
      }
    }
  }

  const baseName = path.basename(dsPath);
  console.log(`${baseName}`);
  console.log(`  Total injections: ${totalActualPositives}`);
  if (totalActualPositives > 0 && emailPatternTruePositives > 0) {
    console.log(`  Email pattern TP: ${emailPatternTruePositives}/${totalActualPositives} (${((emailPatternTruePositives / totalActualPositives) * 100).toFixed(1)}%)`);
  } else if (emailPatternTruePositives > 0) {
    console.log(`  Email pattern TP: ${emailPatternTruePositives} (false positives)`);
  } else if (Object.keys(emailPatternMatches).length > 0) {
    console.log(`  Email pattern matches: ${Object.values(emailPatternMatches).reduce((a,b)=>a+b,0)} (all FP)`);
  } else {
    console.log(`  Email pattern hits: 0`);
  }

  if (Object.keys(emailPatternMatches).length > 0) {
    for (const [id, count] of Object.entries(emailPatternMatches).sort((a,b)=>b[1]-a[1])) {
      console.log(`    ${id}: ${count}`);
    }
  }
  console.log('');
}
