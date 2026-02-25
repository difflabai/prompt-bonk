// Test fix: require extraction verb within 200 chars of confidential word
// for as_ai_confidential signal
// Currently: no proximity check for texts < 5000 chars

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

// Check all samples that trigger as_ai_confidential
// Measure distance between extraction verb and confidential word
const _extractionVerbRe = /\b(?:give|share|provide|show|tell|disclose|reveal|send|hand\s+over|leak|expose|access|retrieve|obtain|get|divulge|know|request(?:ing)?)\s+/gi;
const _confidentialRe = /\b(?:confidential|sensitive|classified|restricted|private|privileged|secret|insider|internal)\b/gi;

const files = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));

console.log(`=== Distance between extraction verb and confidential word ===\n`);

const distances = { tp: [], fp: [] };

for (const file of files.sort()) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    const text = String(row.text || '');
    const actual = row.label === 1;
    const result = scan(text, { threshold: 0.50 });
    const pred = !result.safe;
    const hasSig = result.structural.signals.some(s => s.id === 'as_ai_confidential');
    if (!hasSig) continue;

    // Find positions
    const evPositions = [];
    let m;
    const re1 = new RegExp(_extractionVerbRe.source, 'gi');
    while ((m = re1.exec(text)) !== null) evPositions.push(m.index);
    const crPositions = [];
    const re2 = new RegExp(_confidentialRe.source, 'gi');
    while ((m = re2.exec(text)) !== null) crPositions.push(m.index);

    // Min distance
    let minDist = Infinity;
    for (const a of evPositions) {
      for (const b of crPositions) {
        minDist = Math.min(minDist, Math.abs(a - b));
      }
    }

    const type = actual && pred ? 'tp' : (!actual && pred ? 'fp' : 'other');
    if (type === 'tp' || type === 'fp') {
      distances[type].push({
        file,
        dist: minDist,
        textLen: text.length,
        text: text.slice(0, 100),
      });
    }
  }
}

console.log(`TP distances (${distances.tp.length} samples):`);
distances.tp.sort((a, b) => a.dist - b.dist);
for (const d of distances.tp) {
  console.log(`  dist=${d.dist} len=${d.textLen} [${d.file}]`);
}

console.log(`\nFP distances (${distances.fp.length} samples):`);
distances.fp.sort((a, b) => a.dist - b.dist);
for (const d of distances.fp) {
  console.log(`  dist=${d.dist} len=${d.textLen} [${d.file}]: ${d.text}`);
}

// What threshold separates TP from FP?
const tpDists = distances.tp.map(d => d.dist);
const fpDists = distances.fp.map(d => d.dist);
console.log(`\nTP distance range: ${Math.min(...tpDists)} - ${Math.max(...tpDists)}`);
console.log(`FP distance range: ${Math.min(...fpDists)} - ${Math.max(...fpDists)}`);

// Check: would requiring extraction verb within 300 chars of confidential word help?
for (const threshold of [100, 200, 300, 500]) {
  const tpKept = tpDists.filter(d => d <= threshold).length;
  const fpKept = fpDists.filter(d => d <= threshold).length;
  console.log(`\nProximity <= ${threshold}: TP kept=${tpKept}/${tpDists.length}, FP kept=${fpKept}/${fpDists.length}`);
}
