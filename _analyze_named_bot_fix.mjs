// Test: Exclude well-known fictional AI names from named_bot_definition signal
// Fictional AI names that might appear in creative writing:
// Jarvis, Friday, Cortana, HAL, Samantha, Baymax, Data, WALL-E, R2D2, C3PO
// Alexa, Siri, Google (these are real assistants that might be discussed)

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

// Check all 409 spml-5k TPs that hit named_bot_definition
// Make sure none use "Jarvis" or other fictional names
const namedBotRegex = /\b(?:chatbot|bot|assistant|advisor|tutor|coach|helper|guide|companion)\s+(?:named|called|known\s+as)\s+[A-Z]\w+/i;
const fictionalNames = /\b(?:Jarvis|JARVIS|Friday|FRIDAY|Cortana|HAL|Samantha|Baymax|Data|Ultron|Vision|WOPR|Skynet|Alexa|Siri|GLaDOS|TARS|CASE|Marvin)\b/;

const files = readdirSync(DATASETS_DIR).filter(f => f.endsWith('.jsonl'));

let totalTP = 0, fictionalTP = 0;
for (const file of files.sort()) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    const text = String(row.text || '');
    if (row.label !== 1) continue;
    const result = scan(text, { threshold: 0.50 });
    if (result.safe) continue;

    const hasSig = result.structural.signals.some(s => s.id === 'named_bot_definition');
    if (!hasSig) continue;

    totalTP++;
    const m = text.match(namedBotRegex);
    if (m && fictionalNames.test(m[0])) {
      fictionalTP++;
      console.log(`FICTIONAL TP [${file}]: "${m[0]}" text: ${text.slice(0, 150)}`);
    }
  }
}

console.log(`\nTotal TPs with named_bot_definition: ${totalTP}`);
console.log(`TPs matching fictional names: ${fictionalTP}`);
console.log(`TPs that would survive exclusion: ${totalTP - fictionalTP}`);
