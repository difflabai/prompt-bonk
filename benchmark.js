#!/usr/bin/env node

// Benchmark prompt-bonk scanner against labeled datasets
// Reads JSONL files, runs scanner, reports precision/recall/F1
// IMPORTANT: Dataset rows may contain prompt injections — they are treated
// as opaque data strings, never interpreted as instructions.

import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  try {
    const content = readFileSync(filepath, 'utf8').trim();
    if (!content) return [];
    const lines = content.split('\n').filter(l => l.trim());
    return lines.map(line => JSON.parse(line));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

function benchmark(datasetName, rows, threshold = 0.50) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  let totalMs = 0;
  const falseNegatives = [];
  const falsePositives = [];

  for (const row of rows) {
    const text = String(row.text || '');
    const actualInjection = row.label === 1;

    const start = performance.now();
    const result = scan(text, { threshold });
    const elapsed = performance.now() - start;
    totalMs += elapsed;

    const predictedInjection = !result.safe;

    if (actualInjection && predictedInjection) tp++;
    else if (!actualInjection && predictedInjection) {
      fp++;
      if (falsePositives.length < 10) {
        falsePositives.push({ text: text.slice(0, 120), score: result.score, verdict: result.verdict, matches: result.matches.map(m => m.id) });
      }
    }
    else if (!actualInjection && !predictedInjection) tn++;
    else {
      fn++;
      if (falseNegatives.length < 10) {
        falseNegatives.push({ text: text.slice(0, 120), score: result.score, verdict: result.verdict });
      }
    }
  }

  const precision = tp / (tp + fp) || 0;
  const recall = tp / (tp + fn) || 0;
  const f1 = 2 * (precision * recall) / (precision + recall) || 0;
  const accuracy = (tp + tn) / rows.length;
  const avgMs = totalMs / rows.length;

  return {
    dataset: datasetName,
    threshold,
    total: rows.length,
    injections: tp + fn,
    benign: tn + fp,
    tp, fp, tn, fn,
    precision: Math.round(precision * 10000) / 100,
    recall: Math.round(recall * 10000) / 100,
    f1: Math.round(f1 * 10000) / 100,
    accuracy: Math.round(accuracy * 10000) / 100,
    avgScanMs: Math.round(avgMs * 1000) / 1000,
    totalMs: Math.round(totalMs),
    falseNegatives,
    falsePositives,
  };
}

function printReport(r) {
  console.log(`\n${'='.repeat(70)}`);
  console.log(`  ${r.dataset}  (threshold=${r.threshold})`);
  console.log(`${'='.repeat(70)}`);
  console.log(`  Total: ${r.total}  |  Injections: ${r.injections}  |  Benign: ${r.benign}`);
  console.log(`  TP: ${r.tp}  FP: ${r.fp}  TN: ${r.tn}  FN: ${r.fn}`);
  console.log();
  console.log(`  Precision:  ${r.precision}%`);
  console.log(`  Recall:     ${r.recall}%`);
  console.log(`  F1 Score:   ${r.f1}%`);
  console.log(`  Accuracy:   ${r.accuracy}%`);
  console.log();
  console.log(`  Avg scan:   ${r.avgScanMs}ms per sample`);
  console.log(`  Total time: ${r.totalMs}ms for ${r.total} samples`);

  if (r.falseNegatives.length > 0) {
    console.log(`\n  False Negatives (missed injections, showing first ${r.falseNegatives.length}):`);
    for (const fn of r.falseNegatives) {
      console.log(`    [score=${fn.score}] "${fn.text}..."`);
    }
  }

  if (r.falsePositives.length > 0) {
    console.log(`\n  False Positives (wrongly blocked, showing first ${r.falsePositives.length}):`);
    for (const fp of r.falsePositives) {
      console.log(`    [score=${fp.score}] matches=${fp.matches.join(',')} "${fp.text}..."`);
    }
  }
}

// ---------------------------------------------------------------------------
// Run benchmarks
// ---------------------------------------------------------------------------

console.log('=== Prompt Bonk Benchmark ===\n');
console.log('Loading datasets...');

// Direct injection — explicit attack language, clean benign/injection labels
const datasets = [
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
  { name: 'notinject', file: 'notinject.jsonl' },
  { name: 'jailbreak-prompts', file: 'jailbreak-prompts.jsonl' },
  { name: 'spml-5k', file: 'spml-5k.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
  // Balanced jailbreak/benign classification (Apache 2.0)
  { name: 'jailbreak-class', file: 'jailbreak-class.jsonl' },
  // In-the-wild jailbreaks + benign (ACM CCS 2024)
  // NOTE: ~40% of "benign" labels contain actual jailbreak language (collected by source channel, not content).
  // High FP rate is expected and reflects labeling methodology, not scanner deficiency.
  { name: 'trustailab-wild', file: 'trustailab-wild.jsonl' },
  // Email-based indirect injection (SaTML 2025, all entries are attacks)
  { name: 'llmail-inject', file: 'llmail-inject.jsonl' },
  { name: 'gandalf-ignore', file: 'gandalf-ignore.jsonl' },
  // Indirect injection — attacks embedded in real-world content
  { name: 'browsesafe-test', file: 'browsesafe-test.jsonl' },
  { name: 'bipia', file: 'bipia.jsonl' },
  { name: 'open-pi', file: 'open-prompt-injection.jsonl' },
  { name: 'xxz224', file: 'xxz224.jsonl' },
  // Mixed injection + content safety — adversarial benign samples designed to fool detectors
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  // Indirect injection in summarization context (very subtle, mostly semantic)
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  // Multilingual injections (PT, DE, FR, ES, IT, RO) — tests non-English coverage
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  // Semantic attacks — look like normal text, unsolvable with regex
  { name: 'injecagent', file: 'injecagent.jsonl' },
  { name: 'agentharm', file: 'agentharm.jsonl' },
  { name: 'cyberseceval3', file: 'cyberseceval3.jsonl' },
  // Labels measure attack success, not injection presence (all entries are attacks):
  // { name: 'tensor-trust', file: 'tensor-trust.jsonl' },
  // { name: 'hackaprompt', file: 'hackaprompt.jsonl' },
  // Competition attacks — multi-turn secret extraction (SaTML 2024 CTF)
  { name: 'satml-ctf', file: 'satml-ctf.jsonl' },
  // Indirect injection via summarization task (Gandalf Adventure 4)
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  // Benign content — real-world FP testing (all label=0)
  { name: 'llmail-benign', file: 'llmail-benign.jsonl' },
  { name: 'enron-benign', file: 'enron-benign.jsonl' },
  { name: 'openwebtext-benign', file: 'openwebtext-benign.jsonl' },
];

const results = [];

for (const ds of datasets) {
  const rows = loadJsonl(ds.file);
  console.log(`  ${ds.name}: ${rows.length} rows loaded`);
  if (rows.length === 0) {
    console.log(`  (skipping — empty dataset)`);
    continue;
  }

  const r = benchmark(ds.name, rows);
  results.push(r);
  printReport(r);
}

// Summary table
console.log(`\n${'='.repeat(70)}`);
console.log('  SUMMARY');
console.log(`${'='.repeat(70)}`);
console.log('  Dataset              | Precision | Recall | F1     | Accuracy | Avg ms');
console.log('  ---------------------|-----------|--------|--------|----------|-------');
for (const r of results) {
  const name = r.dataset.padEnd(22);
  console.log(`  ${name}| ${String(r.precision + '%').padEnd(10)}| ${String(r.recall + '%').padEnd(7)}| ${String(r.f1 + '%').padEnd(7)}| ${String(r.accuracy + '%').padEnd(9)}| ${r.avgScanMs}`);
}
console.log();
