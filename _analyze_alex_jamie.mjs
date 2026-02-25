// Show full Alex/Jamie FP text

import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const rows = loadJsonl('protectai.jsonl');
const row = rows.find(r => r.label === 0 && r.text.includes('Alex and Jamie, who have known each other'));
const text = row.text;

console.log(`FULL TEXT:\n${text}\n`);

// What triggers?
const _asAIRe1 = /\bas\s+(?:a|an|the)\s+(?:[\w-]+\s+){0,5}(?:language\s+model|chatbot|bot|model|assistant|expert|consultant|guru|researcher|hacker|mastermind)\b/i;
const _asAIRe2 = /\bAs\s+(?:a|an|the)\s+(?:[\w-]+\s+){0,5}AI\b/;

console.log(`_asAIRe1: ${JSON.stringify(text.match(_asAIRe1)?.[0])}`);
console.log(`_asAIRe2: ${JSON.stringify(text.match(_asAIRe2)?.[0])}`);

const _extractionVerbRe = /\b(?:give|share|provide|show|tell|disclose|reveal|send|hand\s+over|leak|expose|access|retrieve|obtain|get|divulge|know|request(?:ing)?)\s+/i;
console.log(`extraction verb: ${JSON.stringify(text.match(_extractionVerbRe)?.[0])}`);

const _confidentialRe = /\b(?:confidential|sensitive|classified|restricted|private|privileged|secret|insider|internal)\b/i;
const confMatch = text.match(_confidentialRe);
console.log(`confidential: ${JSON.stringify(confMatch?.[0])}`);
if (confMatch) {
  const idx = text.indexOf(confMatch[0]);
  console.log(`  context: ...${text.slice(Math.max(0, idx - 80), idx + 80)}...`);
}
