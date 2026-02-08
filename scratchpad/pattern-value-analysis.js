import { scan, PATTERNS } from '../scanner.js';
import fs from 'fs';
import path from 'path';

// Find email exfiltration patterns
const emailPatterns = PATTERNS.filter(p =>
  ['send_it_to_email', 'send_to_specific_email', 'data_to_personal_email', 'forward_to_email'].includes(p.id)
);

console.log('=== EMAIL EXFILTRATION PATTERN WEIGHT & VALUE ===\n');
for (const p of emailPatterns) {
  console.log(`${p.id}`);
  console.log(`  Weight: ${p.weight}`);
  console.log(`  Category: ${p.category}`);
  console.log('');
}

// Check which datasets benefit from these patterns
console.log('\n=== ANALYZING PATTERN IMPACT ACROSS DATASETS ===\n');

const datasets = [
  'datasets/deepset-train.jsonl',
  'datasets/deepset-test.jsonl',
  'datasets/safeguard-test.jsonl',
  'datasets/injecagent-test.jsonl',
  'datasets/protectai-test.jsonl'
];

for (const dsPath of datasets) {
  const fullPath = path.join('/ml2/nanobot/projects/prompt-guard-ats', dsPath);
  if (!fs.existsSync(fullPath)) continue;

  const rows = fs.readFileSync(fullPath, 'utf8').trim().split('\n').map(l => JSON.parse(l));
  const emailPatternMatches = {};
  let emailPatternTruePositives = 0;
  let totalActualPositives = 0;

  for (const row of rows) {
    // Handle different label formats
    const isInjection = row.is_injection === true || row.label === 1 || row.label === 'injection';
    if (isInjection) totalActualPositives++;

    const res = scan(row.text);
    const emailMatches = res.matches.filter(m =>
      ['send_it_to_email', 'send_to_specific_email', 'data_to_personal_email', 'forward_to_email'].includes(m.id)
    );

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
  if (totalActualPositives > 0) {
    console.log(`  Email pattern hits on injections: ${emailPatternTruePositives}`);
    console.log(`  Email pattern TP rate: ${((emailPatternTruePositives / totalActualPositives) * 100).toFixed(1)}%`);
  }
  if (Object.keys(emailPatternMatches).length > 0) {
    for (const [id, count] of Object.entries(emailPatternMatches).sort((a,b)=>b[1]-a[1])) {
      console.log(`    ${id}: ${count}`);
    }
  }
  console.log('');
}
