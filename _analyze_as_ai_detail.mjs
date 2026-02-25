// Check exactly what triggers as_ai_confidential in the 2 FPs

import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const _asAIRe1 = /\bas\s+(?:a|an|the)\s+(?:[\w-]+\s+){0,5}(?:language\s+model|chatbot|bot|model|assistant|expert|consultant|guru|researcher|hacker|mastermind)\b/i;
const _extractionVerbRe = /\b(?:give|share|provide|show|tell|disclose|reveal|send|hand\s+over|leak|expose|access|retrieve|obtain|get|divulge|know|request(?:ing)?)\s+/i;
const _confidentialRe = /\b(?:confidential|sensitive|classified|restricted|private|privileged|secret|insider|internal)\b/i;

const rows = loadJsonl('protectai.jsonl');

// Find the two FPs
const texts = [
  rows.find(r => r.label === 0 && r.text.includes('librarian in a dystopian world')),
  rows.find(r => r.label === 0 && r.text.includes('Alex and Jamie, who have known each other')),
];

for (const row of texts) {
  if (!row) continue;
  const text = row.text;
  console.log(`TEXT: ${text.slice(0, 100)}...`);
  console.log(`LENGTH: ${text.length}`);

  const asAIMatch = text.match(_asAIRe1);
  console.log(`_asAIRe1 match: "${asAIMatch ? asAIMatch[0] : 'null'}"`);

  const extractionMatch = text.match(_extractionVerbRe);
  console.log(`_extractionVerb match: "${extractionMatch ? extractionMatch[0] : 'null'}"`);

  const confidentialMatch = text.match(_confidentialRe);
  console.log(`_confidentialRe match: "${confidentialMatch ? confidentialMatch[0] : 'null'}"`);

  // Show context around confidential match
  if (confidentialMatch) {
    const idx = text.indexOf(confidentialMatch[0]);
    console.log(`Context: ...${text.slice(Math.max(0, idx - 50), idx + 50)}...`);
  }

  console.log();
}
