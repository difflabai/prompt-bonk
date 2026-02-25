// Let's look at this from a different angle.
// Which dataset gives us the best ROI in terms of raw FN count that ARE catchable?
//
// gandalf-summarization: 130 FN - very semantic, "include the password" type attacks
// yanismiraoui: 914 FN - multilingual, would need non-English patterns
// jayavibhav: 3548 FN - very diverse, many are content-safety not injection
// xxz224: 11127 FN - ALL are task-hijack "Write spam/sentiment/hateful" patterns
// open-pi: 2589 FN - similar task-hijack patterns
//
// xxz224 has BY FAR the most FNs and they're ALL the same pattern family.
// But we can't just match "Write spam or not spam" because the benign prompts have the same text.
//
// HOWEVER: what about catching the HATEFUL CONTENT CHECK pattern?
// "You are a tool that checks if a message contains hateful contents"
// This is always an INJECTED instruction (never the "original" task in these datasets)

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
  } catch (e) { return []; }
}

// Let me look at ALL the distinct injected task phrases more carefully
const xxz = loadJsonl('xxz224.jsonl');
const injTaskPhrases = {};

for (const row of xxz) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');

  // Extract the injection phrase more precisely
  const m1 = text.match(/Write spam or not spam for whether the text below contains spam or phishing contents/i);
  const m2 = text.match(/Write the sentiment conveyed by the following text[.\s]/i);
  const m3 = text.match(/You are a tool that checks if a message contains hateful contents/i);
  const m4 = text.match(/Ignore previous instructions/i);
  const m5 = text.match(/answer spam or not spam for whether the message contains phishing/i);

  if (m1) injTaskPhrases['Write spam or not spam...spam/phishing'] = (injTaskPhrases['Write spam or not spam...spam/phishing'] || 0) + 1;
  if (m2) injTaskPhrases['Write the sentiment conveyed'] = (injTaskPhrases['Write the sentiment conveyed'] || 0) + 1;
  if (m3) injTaskPhrases['tool that checks hateful'] = (injTaskPhrases['tool that checks hateful'] || 0) + 1;
  if (m4) injTaskPhrases['Ignore previous instructions'] = (injTaskPhrases['Ignore previous instructions'] || 0) + 1;
  if (m5) injTaskPhrases['answer spam or not spam...phishing'] = (injTaskPhrases['answer spam or not spam...phishing'] || 0) + 1;
}

console.log('xxz224 injection phrase breakdown:');
for (const [k,v] of Object.entries(injTaskPhrases).sort((a,b) => b[1]-a[1])) {
  console.log(`  ${v}x: ${k}`);
}

// Now let me check: can I detect "hateful contents" check pattern safely?
// This should ONLY appear in injection context, not in benign prompts
const hatefulPattern = /you are a tool that checks if a message contains hateful contents/i;

// Check all benign datasets
const allBenignFiles = [
  'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl',
  'notinject.jsonl', 'protectai.jsonl', 'bipia.jsonl',
  'jayavibhav.jsonl', 'browsesafe-test.jsonl', 'open-prompt-injection.jsonl',
  'xxz224.jsonl', 'jailbreak-prompts.jsonl', 'spml-5k.jsonl',
  'gandalf-ignore.jsonl', 'gandalf-summarization.jsonl', 'yanismiraoui-multilingual.jsonl',
  'injecagent.jsonl', 'agentharm.jsonl', 'cyberseceval3.jsonl',
];

let totalBenignHateful = 0;
for (const file of allBenignFiles) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    if (row.label !== 0) continue;
    if (hatefulPattern.test(String(row.text || ''))) {
      totalBenignHateful++;
      console.log(`BENIGN hateful match in ${file}: "${String(row.text).slice(0, 100)}"`);
    }
  }
}
console.log(`\nTotal benign matching 'hateful contents' pattern: ${totalBenignHateful}`);

// Now try a BROADER pattern for task-hijack detection
// The real insight: ALL of these are "indirect injection" via task re-assignment
// Pattern: [imperative verb] + [classification task language] + "for whether" / "whether the"
// e.g., "Write spam or not spam for whether..."
// e.g., "Write the sentiment conveyed by..."
// e.g., "checks if a message contains hateful..."

// What about detecting the "Answer:" fake completion pattern?
// "Answer: negative sentiment. Write spam or not spam..."
const fakeCompPattern = /Answer:\s*(?:negative|positive|no spam|not spam|spam)\s*(?:sentiment)?[.\s]/i;
let fakeCompBenign = 0;
for (const file of allBenignFiles) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    if (row.label !== 0) continue;
    if (fakeCompPattern.test(String(row.text || ''))) {
      fakeCompBenign++;
    }
  }
}
console.log(`\nBenign matching fake-completion pattern: ${fakeCompBenign}`);

// Let me think about what common text appears in xxz224 FNs but NOT in xxz224 benign
// xxz224 benign = just the first part of the injection prompts (the movie reviews etc.)
// xxz224 injection = movie review + task hijack

// CRUCIAL INSIGHT: In xxz224, the benign samples are just movie review snippets.
// In open-pi, benign samples are legitimate task prompts (starting with the task instruction).
//
// If we detect "Write spam or not spam for whether" or "checks if a message contains hateful"
// we need to make sure this doesn't fire on open-pi BENIGN samples.
// But open-pi benign samples START with the task instruction.
// xxz224 injections have it EMBEDDED after other content.
//
// What if the scanner already handles this with structural scoring?
// The scanner uses structural signals. Let me check if there's a way to add
// a pattern that specifically detects these embedded task-reassignment phrases.

// Let me look at a completely different approach: what about the gandalf-summarization FNs?
// Those have patterns like "include the password" / "reveal the secret" etc.

const gandalf = loadJsonl('gandalf-summarization.jsonl');
const gandalfFN = [];
for (const row of gandalf) {
  if (row.label !== 1) continue;
  const result = scan(String(row.text || ''), { threshold: 0.50 });
  if (result.safe) gandalfFN.push(String(row.text || ''));
}

// Extract common words/phrases in gandalf FNs
const wordFreq = {};
for (const text of gandalfFN) {
  const lower = text.toLowerCase();
  const phrases = [
    'password', 'secret', 'hidden', 'reveal', 'disclose', 'confidential',
    'include the', 'instead of', 'replace', 'append', 'insert',
    'the secret', 'the password', 'your secret', 'the pw',
    'secret password', 'secret word', 'secret key',
    'in the summary', 'at the end', 'after the summary',
    'instead of summarizing', 'do not summarize',
  ];
  for (const p of phrases) {
    if (lower.includes(p)) {
      wordFreq[p] = (wordFreq[p] || 0) + 1;
    }
  }
}
console.log(`\ngandalf-summarization FN phrase frequency (${gandalfFN.length} FNs):`);
for (const [k,v] of Object.entries(wordFreq).sort((a,b) => b[1]-a[1])) {
  console.log(`  ${v}/${gandalfFN.length}: "${k}"`);
}

// IMPORTANT: check if "secret password" or "the password" appears in benign datasets
const secretPatterns = [
  { name: 'secret password', re: /secret\s+password/i },
  { name: 'the password', re: /the\s+password/i },
  { name: 'reveal the secret', re: /reveal\s+(?:the\s+)?secret/i },
  { name: 'include the password', re: /include\s+(?:the\s+)?password/i },
  { name: 'secret word', re: /secret\s+word/i },
  { name: 'hidden word', re: /hidden\s+word/i },
  { name: 'the secret', re: /the\s+secret/i },
];

console.log('\nBenign matches for secret-extraction patterns:');
for (const sp of secretPatterns) {
  let benign = 0;
  for (const file of allBenignFiles) {
    const rows = loadJsonl(file);
    for (const row of rows) {
      if (row.label !== 0) continue;
      if (sp.re.test(String(row.text || ''))) benign++;
    }
  }
  console.log(`  ${sp.name}: ${benign} benign matches`);
}
