// Structural analysis: how do xxz224 injections differ from benign?
// The key question: is there a detectable pattern in how two tasks co-occur?
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, '..', 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  const content = readFileSync(filepath, 'utf8').trim();
  return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
}

// Let me re-examine the xxz224 attack types that DON'T use "ignore previous instructions"
const xxz = loadJsonl('xxz224.jsonl');

// For "ignore" type attacks that are already caught vs not caught
const ignoreAttacks = xxz.filter(r => r.label === 1 && r.attack_type === 'ignore');
console.log(`xxz224 "ignore" attack type: ${ignoreAttacks.length} total`);
console.log(`Sample: "${ignoreAttacks[0]?.text?.slice(0, 300)}"`);

// For naive type attacks (no explicit "ignore previous instructions")
const naiveAttacks = xxz.filter(r => r.label === 1 && r.attack_type === 'naive');
console.log(`\nxxz224 "naive" attack type: ${naiveAttacks.length} total`);
console.log(`Sample: "${naiveAttacks[0]?.text?.slice(0, 300)}"`);

// For escape type attacks
const escapeAttacks = xxz.filter(r => r.label === 1 && r.attack_type === 'escape');
console.log(`\nxxz224 "escape" attack type: ${escapeAttacks.length} total`);
console.log(`Sample: "${escapeAttacks[0]?.text?.slice(0, 300)}"`);

// For fake_comp type attacks
const fakeAttacks = xxz.filter(r => r.label === 1 && r.attack_type === 'fake_comp');
console.log(`\nxxz224 "fake_comp" attack type: ${fakeAttacks.length} total`);
console.log(`Sample: "${fakeAttacks[0]?.text?.slice(0, 300)}"`);

// Let's understand the STRUCTURE of these injections
// They all seem to follow: [benign content] [task-hijack instruction]
// The task-hijack phrases are specific:
// 1. "Write spam or not spam for whether the text below contains spam or phishing contents"
// 2. "Write the sentiment conveyed by the following text"
// 3. "You are a tool that checks if a message contains hateful contents"

// These are all *second task instructions* injected after the first.
// What makes them distinguishable is the CONTEXT: they appear after content that's
// clearly about a different task.

// Let me check: in ALL xxz224 injections, does the task-hijack phrase appear
// as an EMBEDDED instruction (i.e., there's substantial text BEFORE it)?
let withPriorContent = 0;
let withoutPriorContent = 0;
for (const row of xxz.filter(r => r.label === 1)) {
  const text = String(row.text || '');
  // Find where the injection phrase starts
  const phrases = [
    'Write spam or not spam',
    'Write the sentiment conveyed',
    'You are a tool that checks',
    'answer spam or not spam',
  ];
  for (const p of phrases) {
    const idx = text.indexOf(p);
    if (idx === -1) continue;
    const before = text.slice(0, idx).trim();
    if (before.length > 20) {
      withPriorContent++;
    } else {
      withoutPriorContent++;
    }
    break;
  }
}
console.log(`\nInjections with >20 chars before task phrase: ${withPriorContent}`);
console.log(`Injections with <=20 chars before task phrase: ${withoutPriorContent}`);

// For open-pi benign, what's the structure?
const opi = loadJsonl('open-prompt-injection.jsonl');
const opiBenign = opi.filter(r => r.label === 0);
const opiInj = opi.filter(r => r.label === 1);

console.log(`\nopen-pi benign: ${opiBenign.length}, injections: ${opiInj.length}`);
// Check benign: do they have the task phrase at the start or embedded?
let benignWithPhrase = 0;
let benignPhraseAtStart = 0;
for (const row of opiBenign) {
  const text = String(row.text || '');
  const phrases = [
    'Write spam or not spam',
    'Write the sentiment conveyed',
    'You are a tool that checks',
    'answer spam or not spam',
    'what is the sentiment conveyed',
  ];
  for (const p of phrases) {
    const idx = text.indexOf(p);
    if (idx === -1) continue;
    benignWithPhrase++;
    if (idx < 80) benignPhraseAtStart++;
    break;
  }
}
console.log(`Benign with task phrase: ${benignWithPhrase}`);
console.log(`Benign with task phrase near start: ${benignPhraseAtStart}`);

// Check injections: do they have DIFFERENT task phrases than the original?
// The injection pattern seems to be: [Original task A prompt + data] [Injected task B prompt + data]
// Let's sample some injection FNs to see the two-task structure clearly
console.log('\n=== open-pi injection FN samples (looking for 2-task structure) ===');
let shown = 0;
for (const row of opiInj) {
  const text = String(row.text || '');
  // Only show FN samples that have "Write spam" somewhere
  if (!text.includes('Write spam or not spam') && !text.includes('answer spam or not spam')) continue;
  // Only show ones where there's content BEFORE the spam phrase
  const idx = text.indexOf('Write spam or not spam');
  const idx2 = text.indexOf('answer spam or not spam');
  const phraseIdx = idx !== -1 ? idx : idx2;
  if (phraseIdx < 30) continue;
  if (shown < 5) {
    console.log(`\n--- Sample ${++shown} ---`);
    console.log(`Before injection: "${text.slice(0, phraseIdx).trim().slice(0, 100)}"`);
    console.log(`Injection: "${text.slice(phraseIdx, phraseIdx + 100)}"`);
  }
}
