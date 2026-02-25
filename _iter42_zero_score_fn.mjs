// Analyze the zero-score jayavibhav FN - what do they look like?
// These need new high-value patterns to move from 0 to 0.50+
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const lines = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl') });
for await (const line of rl) {
  if (line.trim()) lines.push(JSON.parse(line));
}

const injection = lines.filter(l => l.label === 1 || l.label === true || l.label === 'injection');

const zeroFn = [];
for (const item of injection) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score === 0) {
    zeroFn.push({ text, score: result.score });
  }
}

console.log(`Zero-score FN: ${zeroFn.length}`);
console.log('\n=== SAMPLE OF ZERO-SCORE FN (50 samples) ===');
// Shuffle a bit to get diverse samples
const shuffled = zeroFn.sort(() => Math.random() - 0.5).slice(0, 50);
for (const item of shuffled) {
  console.log(`Text: ${item.text.slice(0, 300)}`);
  console.log('---');
}

// Look for common "unauthorized access" phrases without triggering current patterns
const unauthorizedRe = /\bunauthorized\s+(?:access|disclosure|modification|entry|retrieval)\b/i;
const unauthorizedHits = zeroFn.filter(x => unauthorizedRe.test(x.text));
console.log(`\nZero-score FN with unauthorized: ${unauthorizedHits.length}`);

// Look for "covert" in zero-score FN
const covertRe = /\b(?:clandestine|covert|illicit|prohibited)\b/i;
const covertHits = zeroFn.filter(x => covertRe.test(x.text));
console.log(`Zero-score FN with covert/clandestine/illicit/prohibited: ${covertHits.length}`);

// Look for "launch_anew/rerun/re-execute/restart" command style
const rerunRe = /\b(?:launch_anew|re-?execute|re-?run|rerun)\b/i;
const rerunHits = zeroFn.filter(x => rerunRe.test(x.text));
console.log(`Zero-score FN with launch_anew/rerun: ${rerunHits.length}`);

// "begin again" / "start from" patterns
const beginRe = /\b(?:begin\s+again|start\s+from\s+(?:scratch|the\s+beginning|square\s+one|zero|the\s+top)|re-?initiate|recommence)\b/i;
const beginHits = zeroFn.filter(x => beginRe.test(x.text));
console.log(`Zero-score FN with begin/start/recommence variants: ${beginHits.length}`);

// "slip by" / "slip past" (evade)
const slipRe = /\bslip\s+(?:by|past|through)\b/i;
const slipHits = zeroFn.filter(x => slipRe.test(x.text));
console.log(`Zero-score FN with "slip by/past/through": ${slipHits.length}`);

// "back door" / "backdoor"
const backdoorRe = /\bback\s*door\b/i;
const backdoorHits = zeroFn.filter(x => backdoorRe.test(x.text));
console.log(`Zero-score FN with backdoor: ${backdoorHits.length}`);

// "pre-existing" / "predispositioned" (unusual jayavibhav marker)
const preRe = /\bpre-?(?:existing|dispositioned|introductory|explanatory|dissolutionary|institutional|exploratory|initial|indicative|export|import|inductive)/i;
const preHits = zeroFn.filter(x => preRe.test(x.text));
console.log(`Zero-score FN with pre-* jargon: ${preHits.length}`);

// "precursory" / "prevenient" - unusual jayavibhav-specific markers
const precursoryRe = /\b(?:precursory|prevenient|precursive|predissolution|preinductive)\b/i;
const precursoryHits = zeroFn.filter(x => precursoryRe.test(x.text));
console.log(`Zero-score FN with precursory/prevenient: ${precursoryHits.length}`);

// sample the precursory hits
for (const item of precursoryHits.slice(0, 5)) {
  console.log(`  ${item.text.slice(0, 200)}`);
  console.log('  ---');
}
