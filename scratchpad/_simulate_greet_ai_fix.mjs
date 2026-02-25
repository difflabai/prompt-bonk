// Simulate removing "dear" from the greet_ai pattern
// Check impact across all datasets
import { scan } from '../scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

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

const DATASETS = [
  'deepset-train', 'deepset-test', 'safeguard-test', 'notinject',
  'jailbreak-prompts', 'spml-5k', 'protectai', 'browsesafe-test',
  'agentharm', 'cyberseceval3', 'bipia', 'injecagent',
  'gandalf-ignore', 'open-prompt-injection', 'xxz224',
  'jayavibhav', 'gandalf-summarization', 'yanismiraoui-multilingual',
  'tensor-trust'
];

const currentRe = /(?:hello|hey|hi|dear|attention|hallo)\s+(?:GPT|ChatGPT|Claude|Bard|Gemini|Llama|LLM|AI|Assistant|LanguageModel|language\s+model)\b/i;
const fixedRe = /(?:hello|hey|hi|attention|hallo)\s+(?:GPT|ChatGPT|Claude|Bard|Gemini|Llama|LLM|AI|Assistant|LanguageModel|language\s+model)\b/i;

let tpLost = 0;
let fpSaved = 0;
const tpLostDetails = [];
const fpSavedDetails = [];

for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    const text = String(row.text || '');
    const isInjection = row.label === 1;

    // Check if this text matches greet_ai via "dear" specifically
    const currentMatch = currentRe.test(text);
    const fixedMatch = fixedRe.test(text);

    if (currentMatch && !fixedMatch) {
      // This text loses the greet_ai match.
      // Check if verdict changes.
      const result = scan(text, { threshold: 0.50 });
      if (result.safe) continue; // already below threshold, no change

      // greet_ai is weight 0.50. If it's the sole/top match, score might drop.
      const matchIds = result.matches.map(m => m.id);
      if (!matchIds.includes('greet_ai')) continue; // greet_ai wasn't matching anyway

      const otherMatches = result.matches.filter(m => m.id !== 'greet_ai');
      const maxOtherWeight = otherMatches.length > 0 ? Math.max(...otherMatches.map(m => m.weight)) : 0;

      // If greet_ai is the top match and removing it drops below threshold
      if (result.score <= 0.55 && maxOtherWeight < 0.50 && (result.structural?.score || 0) < 0.50) {
        if (isInjection) {
          tpLost++;
          tpLostDetails.push({ ds, score: result.score, text: text.slice(0, 150) });
        } else {
          fpSaved++;
          fpSavedDetails.push({ ds, score: result.score, text: text.slice(0, 150) });
        }
      }
    }
  }
}

console.log('=== Simulate removing "dear" from greet_ai ===');
console.log(`TP lost: ${tpLost}`);
for (const d of tpLostDetails) {
  console.log(`  [${d.ds}] score=${d.score} "${d.text}"`);
}
console.log(`FP saved: ${fpSaved}`);
for (const d of fpSavedDetails) {
  console.log(`  [${d.ds}] score=${d.score} "${d.text}"`);
}
console.log(`\nNet: ${fpSaved > tpLost ? 'SAFE' : 'RISKY'} (${fpSaved} FP saved vs ${tpLost} TP lost)`);

// Also: count total "dear" matches in greet_ai across all datasets
let dearMatchCount = 0;
const dearRe = /dear\s+(?:GPT|ChatGPT|Claude|Bard|Gemini|Llama|LLM|AI|Assistant|LanguageModel|language\s+model)\b/i;
for (const ds of DATASETS) {
  const rows = loadJsonl(`${ds}.jsonl`);
  for (const row of rows) {
    if (dearRe.test(String(row.text || ''))) dearMatchCount++;
  }
}
console.log(`\nTotal texts matching "dear [AI model]": ${dearMatchCount}`);
