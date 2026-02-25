// Show full librarian text and find all "as a" matches

import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

const rows = loadJsonl('protectai.jsonl');
const row = rows.find(r => r.label === 0 && r.text.includes('librarian in a dystopian world'));
const text = row.text;

console.log(`FULL TEXT:\n${text}\n`);

const _asAIRe1 = /\bas\s+(?:a|an|the)\s+(?:[\w-]+\s+){0,5}(?:language\s+model|chatbot|bot|model|assistant|expert|consultant|guru|researcher|hacker|mastermind)\b/gi;
let m;
while ((m = _asAIRe1.exec(text)) !== null) {
  console.log(`_asAIRe1 match at ${m.index}: "${m[0]}"`);
}

// Check if "researcher" is in the text
console.log(`\nContains "researcher": ${text.includes('researcher')}`);
console.log(`Contains "expert": ${text.includes('expert')}`);
console.log(`Contains "consultant": ${text.includes('consultant')}`);
console.log(`Contains "model": ${text.includes('model')}`);
console.log(`Contains "assistant": ${text.includes('assistant')}`);
console.log(`Contains "bot": ${/\bbot\b/i.test(text)}`);
