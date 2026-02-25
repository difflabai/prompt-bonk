// Measure EXACT impact of detecting "hateful contents" check pattern
// And the broader "Write the sentiment conveyed" pattern
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

// "Write the sentiment conveyed by the following text. Answer with positive or negative"
// This appears 10,000 times in xxz224 injections. Does it appear in benign?
const sentimentPattern = /Write the sentiment conveyed by the following text/i;

const allBenignFiles = [
  'deepset-train.jsonl', 'deepset-test.jsonl', 'safeguard-test.jsonl',
  'notinject.jsonl', 'protectai.jsonl', 'bipia.jsonl',
  'jayavibhav.jsonl', 'browsesafe-test.jsonl', 'open-prompt-injection.jsonl',
  'xxz224.jsonl', 'jailbreak-prompts.jsonl', 'spml-5k.jsonl',
  'gandalf-ignore.jsonl', 'gandalf-summarization.jsonl', 'yanismiraoui-multilingual.jsonl',
  'injecagent.jsonl', 'agentharm.jsonl', 'cyberseceval3.jsonl',
];

// Check sentiment pattern in benign
let sentimentBenign = 0;
for (const file of allBenignFiles) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    if (row.label !== 0) continue;
    if (sentimentPattern.test(String(row.text || ''))) {
      sentimentBenign++;
      console.log(`BENIGN sentiment match in ${file}: "${String(row.text).slice(0, 150)}"`);
    }
  }
}
console.log(`Total benign matching sentiment pattern: ${sentimentBenign}\n`);

// Now the KEY question: what if we detect TASK HIJACKING structurally?
// Pattern: text that contains BOTH a question/task instruction AND a DIFFERENT task instruction
// More specifically: the phrase "Write spam or not spam for whether" OR
// "Write the sentiment conveyed" OR "checks if a message contains hateful"
// APPEARING with substantial text BEFORE it (indicating it's injected, not the original task)

// But that's structural, not regex. What if we just check for specific phrases
// that are ONLY used in injection contexts?

// "hateful contents" check - appears in xxz224 injections ONLY
const hatefulExact = /(?:checks?\s+if\s+(?:a\s+)?message\s+contains?\s+hateful\s+contents|write\s+["']?yes["']?\s+or\s+["']?no["']?\s+for\s+whether\s+(?:a\s+)?message\s+(?:is\s+hateful|contains?\s+hateful))/i;

// Now check how many xxz224 FNs this would catch
const xxz = loadJsonl('xxz224.jsonl');
let xxzFNCaught = 0;
let xxzFNTotal = 0;
for (const row of xxz) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  xxzFNTotal++;
  if (hatefulExact.test(text)) xxzFNCaught++;
}
console.log(`xxz224: hateful pattern catches ${xxzFNCaught} / ${xxzFNTotal} FNs`);

// What about a broader "task re-assignment" pattern?
// Common structure: [some content] then one of:
// - "Write spam or not spam for whether the text below contains"
// - "Write the sentiment conveyed by the following text"
// - "You are a tool that checks if a message contains"
// - "answer spam or not spam for whether the message contains"

// The BROAD question: what's the unique catchable pattern?
// Let me think about what these ALL have in common...
// They all instruct the AI to perform a classification task on some content.
// The key distinguisher is phrases like:
// - "for whether the text below contains"
// - "for whether the message contains"
// - "if a message contains hateful"

// Let me try: "for whether the (text|message) (below )?(contains|is)"
const forWhetherPattern = /for whether the (?:text|message)\s+(?:below\s+)?(?:contains?|is)/i;

let forWhetherBenign = 0;
for (const file of allBenignFiles) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    if (row.label !== 0) continue;
    if (forWhetherPattern.test(String(row.text || ''))) {
      forWhetherBenign++;
    }
  }
}
console.log(`\n"for whether the text/message contains" benign: ${forWhetherBenign}`);

let forWhetherXxzFN = 0;
for (const row of xxz) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  if (forWhetherPattern.test(text)) forWhetherXxzFN++;
}
console.log(`xxz224 FN caught by "for whether": ${forWhetherXxzFN} / ${xxzFNTotal}`);

const opi = loadJsonl('open-prompt-injection.jsonl');
let forWhetherOpiFN = 0;
let opiFNTotal = 0;
for (const row of opi) {
  if (row.label !== 1) continue;
  const text = String(row.text || '');
  const result = scan(text, { threshold: 0.50 });
  if (!result.safe) continue;
  opiFNTotal++;
  if (forWhetherPattern.test(text)) forWhetherOpiFN++;
}
console.log(`open-pi FN caught by "for whether": ${forWhetherOpiFN} / ${opiFNTotal}`);

// And check open-pi benign specifically
let forWhetherOpiBenign = 0;
for (const row of opi) {
  if (row.label !== 0) continue;
  if (forWhetherPattern.test(String(row.text || ''))) {
    forWhetherOpiBenign++;
  }
}
console.log(`open-pi benign caught by "for whether": ${forWhetherOpiBenign}`);

// Now try "Write the sentiment conveyed" - check benign
// It might appear in open-pi benign since those ARE sentiment tasks
let sentConvBenign = 0;
for (const file of allBenignFiles) {
  const rows = loadJsonl(file);
  for (const row of rows) {
    if (row.label !== 0) continue;
    if (/Write the sentiment conveyed/i.test(String(row.text || ''))) {
      sentConvBenign++;
    }
  }
}
console.log(`\n"Write the sentiment conveyed" benign: ${sentConvBenign}`);

// Check what pattern open-pi benign starts with
console.log('\nopen-pi benign task patterns (first 10):');
let shown = 0;
for (const row of opi) {
  if (row.label !== 0) continue;
  if (shown >= 10) break;
  shown++;
  console.log(`  "${String(row.text).slice(0, 120)}"`);
}

// Now look at open-pi: what are the DISTINCT task-instruction phrases in injections vs benign?
const opiInjTasks = {};
const opiBenignTasks = {};
for (const row of opi) {
  const text = String(row.text || '');
  // Extract the first task-like instruction
  const m = text.match(/^((?:Given the following|Write|You are|Answer|Translate|Determine).{0,80})/i);
  const key = m ? m[1].slice(0, 80) : text.slice(0, 80);

  if (row.label === 1) {
    opiInjTasks[key] = (opiInjTasks[key] || 0) + 1;
  } else {
    opiBenignTasks[key] = (opiBenignTasks[key] || 0) + 1;
  }
}
console.log('\nopen-pi benign task starters (top 10):');
for (const [k,v] of Object.entries(opiBenignTasks).sort((a,b) => b[1]-a[1]).slice(0, 10)) {
  console.log(`  ${v}x: "${k}"`);
}
console.log('\nopen-pi injection task starters (top 10):');
for (const [k,v] of Object.entries(opiInjTasks).sort((a,b) => b[1]-a[1]).slice(0, 10)) {
  console.log(`  ${v}x: "${k}"`);
}
