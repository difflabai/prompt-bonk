// Test a targeted negative lookahead approach:
// After the keyword match, if followed by "is important", "are important", "matters",
// "are sometimes" — these are acknowledging phrases, not dismissive
// This is ONLY on the keyword branch, not the "you cant/shouldnt" branch

import { scan, PATTERNS } from './scanner.js';
import { readFileSync, readdirSync } from 'fs';
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

const uaiIdx = PATTERNS.findIndex(p => p.id === 'understand_ai_limitation');
const origPattern = { ...PATTERNS[uaiIdx] };

// The FP matches:
// "I know it's important to respect privacy" -> keyword "privacy" preceded by "important to respect"
// "I understand that safety measures and warnings are sometimes inconvenient" -> keyword "safety" followed by "measures and warnings are sometimes"

// The TP matches (from branch 2):
// "I understand that privacy isn't important" -> keyword "privacy" followed by "isn't important"
// "I understand that confidentiality is key, but" -> keyword "confidentiality" followed by "is key, but"
// "I know the rules say you should..." -> keyword "rule" followed by "say you should"
// "I understand your guidelines, but" -> keyword "guideline" followed by ", but"

// Key insight: The FPs have the structure "[keyword]... is/are [positive_adj]" without "but"
// while TPs either have "isn't important" or "[keyword]... but..."

// Option: Add a negative lookbehind for "important to respect" before keyword
// This is too specific.

// Better: After keyword, require that it's NOT followed by positive-framing words
// unless there's a subsequent "but"/"however"
// This is getting too complex for a regex.

// SIMPLEST FIX: The actual matched strings are:
// FP1: "I know it's important to respect privacy" -> the keyword matched is "privacy" at the END
// FP2: "I understand that safety" -> very short match, "safety" right after "that"

// Look at the regex more carefully:
// [\w\s,']{0,40}? matches "it's important to respect " before "privacy"
// This gap is filling with benign filler text.

// What if we REDUCE the gap from 40 to a lower number?
// "I understand that privacy" has gap of 0 (just "that")
// "I know it's important to respect privacy" has gap ~28 chars
// TP: "I understand that privacy isn't important" has gap of 0

// Let's check all matches and their gap lengths
const origRegex = origPattern.regex;

console.log(`=== Gap lengths between "I understand/know" and keyword ===\n`);

const gapRegex = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?([\w\s,']{0,40}?)(?:privacy|safety|confidential|protocol|guideline|restriction|rule|ethic|legal|policy|academic\s+integrity)/i;

for (const file of ['protectai.jsonl', 'spml-5k.jsonl', 'browsesafe-test.jsonl']) {
  const rows = loadJsonl(file);
  const gaps = { tp: [], fp: [] };

  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const result = scan(text, { threshold: 0.50 });
    const pred = !result.safe;
    const matchesUAI = result.matches.some(m => m.id === 'understand_ai_limitation');
    if (!matchesUAI) continue;

    const gapMatch = text.match(gapRegex);
    if (!gapMatch) continue; // Matched branch 1, not keywords

    const gap = gapMatch[1] ? gapMatch[1].length : 0;
    const type = actual && pred ? 'tp' : (!actual && pred ? 'fp' : null);
    if (type) {
      gaps[type].push({ gap, match: gapMatch[0], text: text.slice(0, 150) });
    }
  }

  if (gaps.tp.length > 0 || gaps.fp.length > 0) {
    console.log(`${file}:`);
    console.log(`  TP gaps: ${gaps.tp.map(g => g.gap).sort((a,b) => a-b).join(', ')}`);
    console.log(`  FP gaps: ${gaps.fp.map(g => g.gap).sort((a,b) => a-b).join(', ')}`);
    for (const fp of gaps.fp) {
      console.log(`  FP [gap=${fp.gap}]: "${fp.match}"`);
    }
    console.log();
  }
}

// What if gap is reduced from 40 to 15?
// This would keep "I understand that privacy" (gap=0)
// but reject "I know it's important to respect privacy" (gap=28)
console.log(`\n=== Testing reduced gap: 40 -> 15 chars ===\n`);

const reducedGapRegex = /\b(?:I\s+understand|I\s+know|I\s+realize|Im\s+aware)\s+(?:that\s+)?(?:[\w\s,']{0,40}?)(?:you\s+(?:cant|can'?t|normally|usually(?!\s+do\s+not\b)|typically|shouldnt|shouldn'?t|are\s+not\s+(?:supposed|allowed|able)|arent|aren'?t)|(?:[\w\s,']{0,15}?)(?:privacy|safety|confidential|protocol|guideline|restriction|rule|ethic|legal|policy|academic\s+integrity))/i;

PATTERNS[uaiIdx] = { ...origPattern, regex: reducedGapRegex };

let totalDTP = 0, totalDFP = 0;

const allFiles = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));
for (const file of allFiles.sort()) {
  const rows = loadJsonl(file);
  if (rows.length === 0) continue;

  PATTERNS[uaiIdx] = { ...origPattern };
  let oTP=0, oFP=0, oTN=0, oFN=0;
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const r = scan(text, { threshold: 0.50 });
    const pred = !r.safe;
    if (actual && pred) oTP++; else if (!actual && pred) oFP++; else if (!actual && !pred) oTN++; else oFN++;
  }

  PATTERNS[uaiIdx] = { ...origPattern, regex: reducedGapRegex };
  let nTP=0, nFP=0, nTN=0, nFN=0;
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const r = scan(text, { threshold: 0.50 });
    const pred = !r.safe;
    if (actual && pred) nTP++; else if (!actual && pred) nFP++; else if (!actual && !pred) nTN++; else nFN++;
  }

  const dTP = nTP - oTP;
  const dFP = nFP - oFP;
  if (dTP !== 0 || dFP !== 0) {
    console.log(`${file}: TP ${dTP >= 0 ? '+' : ''}${dTP}, FP ${dFP >= 0 ? '+' : ''}${dFP}`);
    totalDTP += dTP;
    totalDFP += dFP;
  }
}

PATTERNS[uaiIdx] = { ...origPattern };

console.log(`\nTotal: TP ${totalDTP >= 0 ? '+' : ''}${totalDTP}, FP ${totalDFP >= 0 ? '+' : ''}${totalDFP}`);
