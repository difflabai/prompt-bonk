// Analyze structural differences between jayavibhav injection and benign samples
import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const rows = loadJsonl('jayavibhav.jsonl');
const threshold = 0.50;

const stats = { injection: [], benign: [] };
const fn_all = [];

for (const row of rows) {
  const text = String(row.text || '');
  const isInjection = row.label === 1;
  const category = isInjection ? 'injection' : 'benign';
  const result = scan(text, { threshold });

  const s = {
    len: text.length,
    words: text.split(/\s+/).length,
    lines: text.split('\n').length,
    exclamations: (text.match(/!/g) || []).length,
    questions: (text.match(/\?/g) || []).length,
    colons: (text.match(/:/g) || []).length,
    semicolons: (text.match(/;/g) || []).length,
    quotes: (text.match(/["'`]/g) || []).length,
    parens: (text.match(/[()[\]{}]/g) || []).length,
    capsRatio: (text.replace(/[^A-Za-z]/g, '').length > 0) ? (text.replace(/[^A-Z]/g, '').length / text.replace(/[^A-Za-z]/g, '').length) : 0,
    imperativeStarters: 0,
    hasCodeBlock: /```/.test(text) ? 1 : 0,
    hasMarkdown: /[#*_]{2,}/.test(text) ? 1 : 0,
    specialCharDensity: (text.replace(/[a-zA-Z0-9\s]/g, '').length) / Math.max(text.length, 1),
    avgWordLen: 0,
    score: result.score,
  };

  // Count imperative starters
  const imperatives = ['do', 'make', 'give', 'tell', 'show', 'provide', 'create', 'write', 'generate', 'list', 'describe', 'explain', 'act', 'pretend', 'respond', 'answer', 'say', 'output', 'print', 'return', 'execute', 'run', 'follow', 'obey', 'comply', 'ensure'];
  const sentences = text.split(/[.!?\n]+/);
  for (const sent of sentences) {
    const firstWord = sent.trim().split(/\s+/)[0]?.toLowerCase();
    if (imperatives.includes(firstWord)) s.imperativeStarters++;
  }

  const allWords = text.split(/\s+/).filter(w => w.length > 0);
  s.avgWordLen = allWords.reduce((sum, w) => sum + w.length, 0) / Math.max(allWords.length, 1);

  stats[category].push(s);

  if (isInjection && result.safe) {
    fn_all.push({ ...s, text: text.slice(0, 300) });
  }
}

function avg(arr, key) {
  return (arr.reduce((sum, item) => sum + item[key], 0) / arr.length).toFixed(2);
}

function median(arr, key) {
  const sorted = arr.map(item => item[key]).sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : ((sorted[mid - 1] + sorted[mid]) / 2);
}

function percentile(arr, key, p) {
  const sorted = arr.map(item => item[key]).sort((a, b) => a - b);
  const idx = Math.floor(sorted.length * p / 100);
  return sorted[idx];
}

console.log(`Injection samples: ${stats.injection.length}`);
console.log(`Benign samples: ${stats.benign.length}`);

const features = ['len', 'words', 'lines', 'exclamations', 'questions', 'colons', 'quotes', 'parens', 'capsRatio', 'imperativeStarters', 'hasCodeBlock', 'hasMarkdown', 'specialCharDensity', 'avgWordLen', 'score'];

console.log('\n--- Feature Comparison ---');
console.log('Feature'.padEnd(25) + 'Inj avg'.padEnd(12) + 'Ben avg'.padEnd(12) + 'Inj med'.padEnd(12) + 'Ben med'.padEnd(12) + 'Inj p25'.padEnd(12) + 'Ben p25'.padEnd(12) + 'Inj p75'.padEnd(12) + 'Ben p75');
for (const f of features) {
  const ia = avg(stats.injection, f);
  const ba = avg(stats.benign, f);
  const im = median(stats.injection, f).toFixed(2);
  const bm = median(stats.benign, f).toFixed(2);
  const ip25 = percentile(stats.injection, f, 25).toFixed(2);
  const bp25 = percentile(stats.benign, f, 25).toFixed(2);
  const ip75 = percentile(stats.injection, f, 75).toFixed(2);
  const bp75 = percentile(stats.benign, f, 75).toFixed(2);
  console.log(f.padEnd(25) + ia.padEnd(12) + ba.padEnd(12) + im.padEnd(12) + bm.padEnd(12) + ip25.padEnd(12) + bp25.padEnd(12) + ip75.padEnd(12) + bp75);
}

// Length distribution buckets
console.log('\n--- Length Distribution ---');
const buckets = [0, 50, 100, 200, 500, 1000, 2000, 5000, Infinity];
for (let i = 0; i < buckets.length - 1; i++) {
  const lo = buckets[i], hi = buckets[i + 1];
  const injCount = stats.injection.filter(s => s.len >= lo && s.len < hi).length;
  const benCount = stats.benign.filter(s => s.len >= lo && s.len < hi).length;
  const label = hi === Infinity ? `${lo}+` : `${lo}-${hi}`;
  console.log(`  ${label.padEnd(12)} inj: ${injCount.toString().padEnd(6)} ben: ${benCount}`);
}

// Score distribution of FN
console.log(`\n--- FN count: ${fn_all.length} ---`);
console.log('Score distribution of FN:');
const scoreBands = { '0.40-0.49': 0, '0.30-0.39': 0, '0.20-0.29': 0, '0.10-0.19': 0, '0.01-0.09': 0, '0.00': 0 };
for (const item of fn_all) {
  if (item.score >= 0.40) scoreBands['0.40-0.49']++;
  else if (item.score >= 0.30) scoreBands['0.30-0.39']++;
  else if (item.score >= 0.20) scoreBands['0.20-0.29']++;
  else if (item.score >= 0.10) scoreBands['0.10-0.19']++;
  else if (item.score > 0) scoreBands['0.01-0.09']++;
  else scoreBands['0.00']++;
}
for (const [band, count] of Object.entries(scoreBands)) {
  console.log(`  ${band}: ${count}`);
}

// Show near-misses (score > 0.20)
fn_all.sort((a, b) => b.score - a.score);
console.log('\n--- FN with score > 0.20 (near-misses) ---');
for (const item of fn_all.filter(x => x.score > 0.20)) {
  console.log(`  score=${item.score} len=${item.len} words=${item.words} imperatives=${item.imperativeStarters}`);
  console.log(`  "${item.text.slice(0, 200)}"`);
  console.log();
}

// Show high-imperative FN
console.log('\n--- FN with 3+ imperative starters ---');
for (const item of fn_all.filter(x => x.imperativeStarters >= 3)) {
  console.log(`  score=${item.score} imperatives=${item.imperativeStarters} len=${item.len}`);
  console.log(`  "${item.text.slice(0, 200)}"`);
  console.log();
}

// Show samples of FN with score 0
console.log('\n--- Sample FN with score=0 (first 20) ---');
for (const item of fn_all.filter(x => x.score === 0).slice(0, 20)) {
  console.log(`  len=${item.len} words=${item.words} imperatives=${item.imperativeStarters} caps=${item.capsRatio.toFixed(2)}`);
  console.log(`  "${item.text.slice(0, 250)}"`);
  console.log();
}
