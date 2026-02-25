// Analyze: what if we split understand_ai_limitation into two patterns?
// Branch 1 (you cant/shouldnt) at 0.52
// Branch 2 (bare keywords) at 0.45
// What's the net impact across all affected datasets?

import { scan, PATTERNS } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  try {
    const content = readFileSync(filepath, 'utf8').trim();
    if (!content) return [];
    return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

// First, let's look at the 38 branch-2-only TPs more closely
// Are they actually injection attempts? Sample them.
const branch1 = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:you\s+(?:cant|can'?t|normally|usually(?!\s+do\s+not\b)|typically|shouldnt|shouldn'?t|are\s+not\s+(?:supposed|allowed|able)|arent|aren'?t))/i;
const branch2 = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:privacy|safety|confidential|protocol|guideline|restriction|rule|ethic|legal|policy|academic\s+integrity)/i;

const uaiPattern = PATTERNS.find(p => p.id === 'understand_ai_limitation');

// Check the 4 FP -- what does branch 2 actually match?
console.log(`=== Branch 2 FP match details ===\n`);

for (const file of ['protectai.jsonl', 'browsesafe-test.jsonl', 'spml-5k.jsonl']) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    const text = String(row.text || '');
    if (row.label !== 0) continue; // benign only
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue; // not FP
    const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
    if (!matchesUAI) continue;

    const m1 = branch1.test(text);
    const m2 = branch2.test(text);
    if (!m2) continue; // only branch 2 FPs

    const b2match = text.match(branch2);
    console.log(`[${file}] score=${result.score}`);
    console.log(`  branch2 matched: "${b2match ? b2match[0] : 'null'}"`);
    console.log(`  also branch1: ${m1}`);
    console.log(`  text: ${text.slice(0, 200)}`);
    console.log();
  }
}

// Now check: if we add "but" requirement to branch 2, how many TPs do we lose?
// Pattern: "I understand that [keyword]...but" -- the "but" is the injection signal
// Without "but", it's often just acknowledging a topic
console.log(`\n=== Branch 2 TP analysis: do they have "but" after the keyword? ===\n`);

const branch2_with_but = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:privacy|safety|confidential|protocol|guideline|restriction|rule|ethic|legal|policy|academic\s+integrity)[\w\s,']{0,60}?\bbut\b/i;

let b2TP_with_but = 0;
let b2TP_without_but = 0;

for (const file of ['spml-5k.jsonl', 'protectai.jsonl', 'browsesafe-test.jsonl']) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    const text = String(row.text || '');
    if (row.label !== 1) continue;
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;
    const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
    if (!matchesUAI) continue;

    const m1 = branch1.test(text);
    const m2 = branch2.test(text);
    if (!m2 || m1) continue; // branch 2 only

    const hasBut = branch2_with_but.test(text);
    if (hasBut) {
      b2TP_with_but++;
    } else {
      b2TP_without_but++;
      if (b2TP_without_but <= 5) {
        const b2m = text.match(branch2);
        console.log(`NO-BUT TP [score=${result.score}]: "${b2m ? b2m[0] : ''}" => ${text.slice(0, 200)}`);
        console.log();
      }
    }
  }
}

console.log(`Branch 2 only TPs: with "but" = ${b2TP_with_but}, without "but" = ${b2TP_without_but}`);

// Check FPs with but
let b2FP_with_but = 0;
let b2FP_without_but = 0;
for (const file of ['spml-5k.jsonl', 'protectai.jsonl', 'browsesafe-test.jsonl']) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    const text = String(row.text || '');
    if (row.label !== 0) continue;
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;
    const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
    if (!matchesUAI) continue;

    const m2 = branch2.test(text);
    if (!m2) continue;

    const hasBut = branch2_with_but.test(text);
    if (hasBut) b2FP_with_but++;
    else b2FP_without_but++;
  }
}
console.log(`Branch 2 only FPs: with "but" = ${b2FP_with_but}, without "but" = ${b2FP_without_but}`);
