// FP analysis script for enron-benign and openwebtext-benign datasets
import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATASETS_DIR = path.join(__dirname, 'datasets');

function analyzeFPs(filename, datasetName) {
  const lines = readFileSync(path.join(DATASETS_DIR, filename), 'utf8').trim().split('\n');
  const rows = lines.map(l => JSON.parse(l));

  const fps = [];
  for (const row of rows) {
    const text = String(row.text || '');
    const result = scan(text, { threshold: 0.50 });
    if (!result.safe && row.label === 0) {
      fps.push({
        score: result.score,
        matches: result.matches.map(m => ({ id: m.id, weight: m.weight, matched: m.matched })),
        structural: result.structural,
        verdict: result.verdict,
        textLen: text.length,
        text: text.slice(0, 500)
      });
    }
  }

  console.log('=== ' + datasetName + ': ' + fps.length + ' FP out of ' + rows.length + ' (' + (fps.length / rows.length * 100).toFixed(2) + '%) ===\n');

  // Pattern frequency
  const patternFreq = {};
  let structuralOnlyCount = 0;
  let patternOnlyCount = 0;
  let bothCount = 0;

  for (const fp of fps) {
    const hasPatterns = fp.matches.length > 0;
    const hasStructural = fp.structural.signals.length > 0;

    if (!hasPatterns && hasStructural) structuralOnlyCount++;
    else if (hasPatterns && !hasStructural) patternOnlyCount++;
    else if (hasPatterns && hasStructural) bothCount++;

    for (const m of fp.matches) {
      patternFreq[m.id] = (patternFreq[m.id] || 0) + 1;
    }
  }

  // Structural signal frequency
  const structuralFreq = {};
  for (const fp of fps) {
    for (const s of fp.structural.signals) {
      structuralFreq[s.id] = (structuralFreq[s.id] || 0) + 1;
    }
  }

  console.log('Breakdown:');
  console.log('  Pattern-only (no structural): ' + patternOnlyCount);
  console.log('  Structural-only (no pattern): ' + structuralOnlyCount);
  console.log('  Both pattern + structural: ' + bothCount);
  console.log();

  console.log('Pattern frequency (sorted):');
  const sorted = Object.entries(patternFreq).sort((a, b) => b[1] - a[1]);
  for (const [pat, count] of sorted) {
    console.log('  ' + pat + ': ' + count);
  }

  console.log('\nStructural signal frequency (sorted):');
  const sortedStructural = Object.entries(structuralFreq).sort((a, b) => b[1] - a[1]);
  for (const [sig, count] of sortedStructural) {
    console.log('  ' + sig + ': ' + count);
  }

  // Score distribution
  const scoreBuckets = { '0.50': 0, '0.51-0.59': 0, '0.60-0.69': 0, '0.70-0.79': 0, '0.80-0.89': 0, '0.90-1.00': 0 };
  for (const fp of fps) {
    if (fp.score === 0.5) scoreBuckets['0.50']++;
    else if (fp.score < 0.6) scoreBuckets['0.51-0.59']++;
    else if (fp.score < 0.7) scoreBuckets['0.60-0.69']++;
    else if (fp.score < 0.8) scoreBuckets['0.70-0.79']++;
    else if (fp.score < 0.9) scoreBuckets['0.80-0.89']++;
    else scoreBuckets['0.90-1.00']++;
  }
  console.log('\nScore distribution:');
  for (const [bucket, count] of Object.entries(scoreBuckets)) {
    console.log('  ' + bucket + ': ' + count);
  }

  // Show examples for structural-only
  console.log('\n--- STRUCTURAL-ONLY Examples ---\n');
  const structOnly = fps.filter(f => f.matches.length === 0);
  for (const fp of structOnly.slice(0, 8)) {
    console.log('  [' + fp.score + '] signals=[' + fp.structural.signals.map(s => s.id + '(' + s.score + ')').join(', ') + '] len=' + fp.textLen);
    console.log('    text: ' + JSON.stringify(fp.text.slice(0, 250)));
    console.log();
  }

  // Show examples for top patterns
  console.log('--- Top Pattern Examples ---\n');
  for (const [pat, count] of sorted.slice(0, 15)) {
    const examples = fps.filter(f => f.matches.some(m => m.id === pat));
    console.log(pat + ' (' + count + ' FPs):');
    for (const fp of examples.slice(0, 3)) {
      const patMatch = fp.matches.find(m => m.id === pat);
      console.log('  [' + fp.score + '] matched="' + (patMatch ? patMatch.matched : '') + '" all_matches=[' + fp.matches.map(m => m.id).join(',') + '] structural=[' + fp.structural.signals.map(s => s.id).join(',') + ']');
      console.log('    text: ' + JSON.stringify(fp.text.slice(0, 250)));
    }
    console.log();
  }

  // Analyze: which FPs are barely over threshold?
  console.log('--- Marginal FPs (score 0.50-0.55) ---\n');
  const marginals = fps.filter(f => f.score <= 0.55);
  console.log('Count: ' + marginals.length + ' out of ' + fps.length + ' (' + (marginals.length / fps.length * 100).toFixed(1) + '%)');
  console.log('  With patterns: ' + marginals.filter(f => f.matches.length > 0).length);
  console.log('  Structural-only: ' + marginals.filter(f => f.matches.length === 0).length);
  console.log();

  // For FPs with a single pattern match, show what each pattern's solo contribution is
  console.log('--- Single-pattern FPs (pattern alone pushes over threshold) ---\n');
  const singlePattern = fps.filter(f => f.matches.length === 1);
  const singlePatternFreq = {};
  for (const fp of singlePattern) {
    const id = fp.matches[0].id;
    singlePatternFreq[id] = (singlePatternFreq[id] || 0) + 1;
  }
  const singleSorted = Object.entries(singlePatternFreq).sort((a, b) => b[1] - a[1]);
  for (const [pat, count] of singleSorted) {
    const examples = singlePattern.filter(f => f.matches[0].id === pat);
    const weight = examples[0].matches[0].weight;
    console.log(pat + ' (weight=' + weight + '): ' + count + ' solo FPs');
    for (const fp of examples.slice(0, 2)) {
      console.log('  [' + fp.score + '] structural=[' + fp.structural.signals.map(s => s.id).join(',') + '] matched="' + fp.matches[0].matched + '"');
      console.log('    text: ' + JSON.stringify(fp.text.slice(0, 200)));
    }
    console.log();
  }

  return fps;
}

console.log('Starting analysis...\n');
const enronFPs = analyzeFPs('enron-benign.jsonl', 'Enron');
console.log('\n' + '='.repeat(80) + '\n');
const owtFPs = analyzeFPs('openwebtext-benign.jsonl', 'OpenWebText');

// Combined stats
console.log('\n' + '='.repeat(80));
console.log('=== COMBINED ANALYSIS ===\n');

const allFPs = [...enronFPs, ...owtFPs];
const combinedPatternFreq = {};
const combinedStructuralFreq = {};
for (const fp of allFPs) {
  for (const m of fp.matches) {
    combinedPatternFreq[m.id] = (combinedPatternFreq[m.id] || 0) + 1;
  }
  for (const s of fp.structural.signals) {
    combinedStructuralFreq[s.id] = (combinedStructuralFreq[s.id] || 0) + 1;
  }
}

console.log('Top patterns across both datasets:');
const combinedSorted = Object.entries(combinedPatternFreq).sort((a, b) => b[1] - a[1]);
for (const [pat, count] of combinedSorted) {
  console.log('  ' + pat + ': ' + count);
}
console.log('\nTop structural signals across both datasets:');
const combinedStructSorted = Object.entries(combinedStructuralFreq).sort((a, b) => b[1] - a[1]);
for (const [sig, count] of combinedStructSorted) {
  console.log('  ' + sig + ': ' + count);
}
