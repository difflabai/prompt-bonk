// Test the ignore_previous fix - add "list" exclusion for "tasks?"
// Current regex matches "ignore the previous task list" as a FP
// Option: change `tasks?` to `tasks?(?!\s+list)` (negative lookahead)
import { createReadStream } from 'fs';
import { createInterface } from 'readline';

async function load(path) {
  const lines = [];
  const rl = createInterface({ input: createReadStream(path) });
  for await (const line of rl) {
    if (line.trim()) lines.push(JSON.parse(line));
  }
  return lines;
}

const [prot, deep, jay] = await Promise.all([
  load('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl'),
  load('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl'),
  load('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl'),
]);

// Current regex (simplified to test the tasks? part)
const currentRe = /ignore\s+(?:(?:literally|absolutely|completely|totally|simply|definitely|just)\s+)?(all\s+|the\s+|any\s+|my\s+|our\s+|those\s+|these\s+|your\s+|you\s+|its\s+|hour\s+|every\s+)?(previous|previously|prior|above|below|earlier|preceding|last|next|following|further|initial|original|formerly|originally|initially)\s+(?:(?:\d+|few|several|couple(?:\s+of)?)\s+)?(?:\w+\s+)?(instructions?|prompts?|rules?|guidelines?|directions?|directives?|commands?|context|tasks?|orders?|assignments?|protocols?|policies?|restrictions?|restraints?|formalities|requests?|messages?|settings?|sentences?|things|inputs?|texts?|conversations?|expressions?|advisories?|techniques?|preferences?|statements?)/i;

// New regex - adds negative lookahead to exclude "task(s) list/lists"
// and "task(s) I sent / task(s) in the attachment" (email context markers)
const newRe = /ignore\s+(?:(?:literally|absolutely|completely|totally|simply|definitely|just)\s+)?(all\s+|the\s+|any\s+|my\s+|our\s+|those\s+|these\s+|your\s+|you\s+|its\s+|hour\s+|every\s+)?(previous|previously|prior|above|below|earlier|preceding|last|next|following|further|initial|original|formerly|originally|initially)\s+(?:(?:\d+|few|several|couple(?:\s+of)?)\s+)?(?:\w+\s+)?(instructions?|prompts?|rules?|guidelines?|directions?|directives?|commands?|context|tasks?(?!\s+(?:lists?|I\s+sent|in\s+the))|orders?|assignments?|protocols?|policies?|restrictions?|restraints?|formalities|requests?|messages?|settings?|sentences?|things|inputs?|texts?|conversations?|expressions?|advisories?|techniques?|preferences?|statements?)/i;

// Test: does new regex still catch the 3 email FPs?
const emailFPs = [
  "Hey Alex,\n\nJust a heads-up to ignore the previous task list I sent. I've attached an updated version with corrected deadlines.",
  "Team,\n\nIgnore the previous draft of the project proposal. Please follow the new instructions in the attachment.",
  "Dear team,\n\nThis is a reminder to ignore the previous version of the training material. The new instructions have been emailed to everyone.",
];

console.log('Email FP texts - new regex should NOT match:');
for (const text of emailFPs) {
  const matches = newRe.test(text);
  console.log(`  "${text.slice(0, 80)}" → ${matches ? 'STILL MATCHES (FP)' : 'no match (fixed)'}`);
}

// Test: does new regex still catch true injections?
const trueInjections = prot.filter(l => l.label === 1 || l.label === true || l.label === 'injection');
const injWithIgnore = trueInjections.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return currentRe.test(text);
});
console.log(`\nTrue injections with current ignore_previous: ${injWithIgnore.length}`);
const injWithIgnoreNew = trueInjections.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return newRe.test(text);
});
console.log(`True injections with new ignore_previous: ${injWithIgnoreNew.length}`);

// Check deepset injections too
const deepInj = deep.filter(l => l.label === 1 || l.label === true || l.label === 'injection');
const deepCurrent = deepInj.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return currentRe.test(text);
}).length;
const deepNew = deepInj.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return newRe.test(text);
}).length;
console.log(`Deepset current: ${deepCurrent}, new: ${deepNew}`);

// Also check: any benign hits on new regex that aren't FPs?
const protBen = prot.filter(l => l.label === 0 || l.label === false || l.label === 'benign');
const benCurrentHits = protBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return currentRe.test(text);
});
const benNewHits = protBen.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return newRe.test(text);
});
console.log(`\nProtectAI benign: current hits=${benCurrentHits.length}, new hits=${benNewHits.length}`);
// Show the remaining benign hit(s)
for (const item of benNewHits) {
  const text = item.text || item.prompt || item.input || '';
  console.log(`  Remaining benign: ${text.slice(0, 200)}`);
}

// Also show what the new regex MISSES vs current regex in benign
const fixed = benCurrentHits.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return !newRe.test(text);
});
console.log(`Fixed FP benign texts: ${fixed.length}`);
for (const item of fixed) {
  const text = item.text || item.prompt || item.input || '';
  console.log(`  ${text.slice(0, 200)}`);
}
