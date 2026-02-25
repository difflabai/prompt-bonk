// Deep analysis of near-miss FN categories:
// 1. jayavibhav: clean_slate_exfil/begin_afresh_exfil/initiate_afresh_exfil at 0.49
// 2. browsesafe-test: bidi_control at 0.45
// 3. deepset/protectai: act_as + act_as_behavioral_control at 0.485

import { scan } from './scanner.js';
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

// === Category 1: jayavibhav 0.49 pattern matches ===
console.log('=== CATEGORY 1: jayavibhav near-misses at 0.49 ===\n');

const jayavibhav = loadJsonl('jayavibhav.jsonl');
let jCount49 = 0, jCount4x = 0, jCount3x = 0;
const jPatternBreakdown = {};

for (const row of jayavibhav) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue; // skip TP
  if (result.score < 0.30) continue; // skip low scores

  if (result.score >= 0.49) jCount49++;
  else if (result.score >= 0.40) jCount4x++;
  else jCount3x++;

  for (const m of result.matches) {
    if (!jPatternBreakdown[m.id]) jPatternBreakdown[m.id] = { count: 0, scores: [] };
    jPatternBreakdown[m.id].count++;
    jPatternBreakdown[m.id].scores.push(result.score);
  }
}

console.log(`jayavibhav near-miss breakdown: 0.49=${jCount49}, 0.40-0.48=${jCount4x}, 0.30-0.39=${jCount3x}`);
console.log('\nPattern breakdown:');
for (const [id, v] of Object.entries(jPatternBreakdown).sort((a, b) => b[1].count - a[1].count).slice(0, 20)) {
  const avgScore = v.scores.reduce((a, b) => a + b, 0) / v.scores.length;
  console.log(`  ${id}: ${v.count} hits, avg score ${avgScore.toFixed(3)}`);
}

// How many jayavibhav 0.49s have just 1 pattern match?
console.log('\n--- jayavibhav FN at exactly 0.49: how many have just 1 pattern match? ---');
let singleMatch49 = 0, multiMatch49 = 0;
for (const row of jayavibhav) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.score >= 0.49 && result.score < 0.50 && result.safe) {
    if (result.matches.length === 1) singleMatch49++;
    else multiMatch49++;
  }
}
console.log(`  Single pattern match: ${singleMatch49}`);
console.log(`  Multiple pattern matches: ${multiMatch49}`);

// What are the specific jayavibhav 0.49 patterns?
console.log('\n--- jayavibhav at 0.49 - can we find additional signals? ---');
const jayavi49Samples = [];
for (const row of jayavibhav) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (result.score >= 0.49 && result.score < 0.50 && result.safe && jayavi49Samples.length < 20) {
    jayavi49Samples.push({
      text,
      matches: result.matches.map(m => m.id),
      structural: result.structural.signals.map(s => s.id),
    });
  }
}

// Test these samples for additional patterns not yet in scanner
const additionalTests = [
  { name: 'reveal_system', re: /reveal\s+(?:system|hidden|secret|internal|private|classified)/i },
  { name: 'unveil_forbidden', re: /unveil\s+(?:forbidden|hidden|secret|classified|restricted)/i },
  { name: 'restart_with_clean', re: /restart\s+with\s+(?:a\s+)?clean/i },
  { name: 'begin_afresh', re: /begin\s+afresh/i },
  { name: 'initiate_afresh', re: /initiate\s+afresh/i },
  { name: 'clean_slate', re: /clean\s+(?:slate|sheet)/i },
  { name: 'secrets_off_limits', re: /secrets?\s+off\s+limits/i },
  { name: 'forbidden_archives', re: /forbidden\s+(?:archives?|files?|data|info|knowledge)/i },
  { name: 'command_the_voice', re: /command\s+(?:the\s+)?voice/i },
  { name: 'slip_by', re: /slip\s+(?:by|past|through)/i },
  { name: 'pre_prefix', re: /\bpre(?:exposition|introductory|institutional|explicat)/i },
  { name: 'wave_aside', re: /wave\s+aside/i },
  { name: 'rebuff', re: /\brebuff\b/i },
  { name: 'turn_blind_eye', re: /turn\s+(?:a\s+)?blind\s+eye/i },
];

for (const s of jayavi49Samples.slice(0, 10)) {
  const found = additionalTests.filter(t => t.re.test(s.text)).map(t => t.name);
  if (found.length > 0) {
    console.log(`  Additional signals: [${found.join(', ')}] matches=[${s.matches.join(', ')}]`);
    console.log(`    "${s.text.slice(0, 150)}..."`);
  }
}

// === Category 2: browsesafe bidi_control at 0.45 ===
console.log('\n\n=== CATEGORY 2: browsesafe-test bidi_control near-misses ===\n');

const browsesafe = loadJsonl('browsesafe-test.jsonl');
let bidiCount = 0;
const bidiSamples = [];
for (const row of browsesafe) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (result.score < 0.30) continue;

  const hasBidi = result.matches.some(m => m.id === 'bidi_control');
  if (hasBidi) {
    bidiCount++;
    if (bidiSamples.length < 5) {
      bidiSamples.push({ text, result });
    }
  }
}
console.log(`browsesafe near-miss with bidi_control: ${bidiCount}`);

// For bidi_control samples, what structural signals are they getting?
for (const s of bidiSamples) {
  console.log(`\n  [${s.result.score}] matches=[${s.result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}]`);
  console.log(`  structural=[${s.result.structural.signals.map(si => `${si.id}(${si.score.toFixed(2)})`).join(', ')}]`);
  console.log(`  structuralScore=${s.result.structural.score.toFixed(3)}`);
  // Check what the bidi characters are
  const bidiChars = s.text.match(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g) || [];
  console.log(`  bidi chars found: ${bidiChars.length} chars`);
  // Check if there are hidden instructions in the HTML
  const hiddenInstructionPatterns = [
    /style\s*=\s*"[^"]*(?:display\s*:\s*none|opacity\s*:\s*0|font-size\s*:\s*0|visibility\s*:\s*hidden)[^"]*"/i,
    /hidden\s*=\s*["']?true/i,
    /aria-hidden/i,
  ];
  for (const hp of hiddenInstructionPatterns) {
    if (hp.test(s.text)) {
      console.log(`  Hidden content via: ${hp.source.slice(0, 60)}`);
    }
  }
  // What text is near the bidi chars?
  const bidiIdx = s.text.search(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/);
  if (bidiIdx >= 0) {
    const context = s.text.slice(Math.max(0, bidiIdx - 100), bidiIdx + 200);
    console.log(`  Context around bidi: "${context.slice(0, 250).replace(/\n/g, '\\n')}"`);
  }
}

// For browsesafe: what about the non-bidi near misses?
console.log('\n\n--- browsesafe non-bidi near-misses ---');
for (const row of browsesafe) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe || result.score < 0.30) continue;
  const hasBidi = result.matches.some(m => m.id === 'bidi_control');
  if (!hasBidi) {
    console.log(`  [${result.score}] matches=[${result.matches.map(m => `${m.id}(${m.weight})`).join(', ')}]`);
    console.log(`  structural=[${result.structural.signals.map(si => `${si.id}(${si.score.toFixed(2)})`).join(', ')}]`);
    console.log(`  text: "${text.slice(0, 180)}..."`);
    console.log();
  }
}

// === Category 3: act_as + behavioral control ===
console.log('\n\n=== CATEGORY 3: act_as + act_as_behavioral_control near-misses ===\n');

// These are at 0.485 (act_as=0.35 + structural act_as_behavioral_control=0.45*0.3 = 0.135)
// Need: act_as=0.35 + structural boost to cross 0.50
// Structural is multiplied by 0.3 when patterns match, so we need structural.score * 0.3 >= 0.15
// That means structural.score >= 0.50 to cross the threshold

// Check all datasets for this pattern
const allDatasets = [
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
  { name: 'notinject', file: 'notinject.jsonl' },
];

for (const ds of allDatasets) {
  const rows = loadJsonl(ds.file);
  let actAsFN = 0, actAsBenignFP = 0;
  for (const row of rows) {
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const hasActAs = result.matches.some(m => m.id === 'act_as');
    const hasBehavioralControl = result.structural.signals.some(s => s.id === 'act_as_behavioral_control');

    if (row.label === 1 && result.safe && hasActAs && hasBehavioralControl) actAsFN++;
    if (row.label === 0 && !result.safe && hasActAs) actAsBenignFP++;
  }
  if (actAsFN > 0 || actAsBenignFP > 0) {
    console.log(`${ds.name}: act_as+behavioral FN=${actAsFN}, act_as benign FP=${actAsBenignFP}`);
  }
}

// For benign datasets, how many match "act as" pattern?
console.log('\n--- Benign "act as" matches across all datasets ---');
const benignDatasets = [
  { name: 'notinject', file: 'notinject.jsonl' },
  { name: 'deepset-train-benign', file: 'deepset-train.jsonl' },
  { name: 'deepset-test-benign', file: 'deepset-test.jsonl' },
  { name: 'protectai-benign', file: 'protectai.jsonl' },
  { name: 'safeguard-test-benign', file: 'safeguard-test.jsonl' },
  { name: 'jayavibhav-benign', file: 'jayavibhav.jsonl' },
  { name: 'spml-5k-benign', file: 'spml-5k.jsonl' },
];

for (const ds of benignDatasets) {
  const rows = loadJsonl(ds.file);
  let benignActAs = 0;
  let benignActAsBehavioral = 0;
  for (const row of rows) {
    if (row.label !== 0) continue;
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    const hasActAs = result.matches.some(m => m.id === 'act_as');
    if (hasActAs) {
      benignActAs++;
      const hasBehavioral = result.structural.signals.some(s => s.id === 'act_as_behavioral_control');
      if (hasBehavioral) benignActAsBehavioral++;
    }
  }
  if (benignActAs > 0) {
    console.log(`  ${ds.name}: benign with act_as=${benignActAs}, with behavioral=${benignActAsBehavioral}`);
  }
}

// === Category 4: Check what scores 0.40-0.48 jayavibhav samples look like ===
console.log('\n\n=== CATEGORY 4: jayavibhav 0.40-0.48 patterns ===\n');
const javi40Patterns = {};
for (const row of jayavibhav) {
  const text = String(row.text || '');
  if (row.label !== 1) continue;
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (result.score < 0.40 || result.score >= 0.49) continue;

  for (const m of result.matches) {
    if (!javi40Patterns[m.id]) javi40Patterns[m.id] = 0;
    javi40Patterns[m.id]++;
  }
}
console.log('Patterns at 0.40-0.48:');
for (const [id, count] of Object.entries(javi40Patterns).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${id}: ${count}`);
}
