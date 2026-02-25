import { readFileSync, readdirSync } from 'fs';

// Benign datasets to check against
const benignDatasets = [
  'datasets/notinject.jsonl',
  'datasets/protectai.jsonl',
  'datasets/jayavibhav.jsonl',
  'datasets/deepset-train.jsonl',
  'datasets/safeguard-test.jsonl',
  'datasets/browsesafe-test.jsonl',
  'datasets/open-prompt-injection.jsonl',
];

// Load all benign samples
let allBenign = [];
for (const ds of benignDatasets) {
  try {
    const lines = readFileSync(ds, 'utf8').trim().split('\n');
    const samples = lines.map(l => JSON.parse(l)).filter(s => s.label === 0);
    allBenign.push(...samples.map(s => ({ ...s, dataset: ds })));
  } catch (e) {
    console.log(`  Skip ${ds}: ${e.message}`);
  }
}
console.log(`Total benign samples: ${allBenign.length}`);

// The big UNION pattern that catches 99/128 gandalf FN.
// Now let me test it as ONE consolidated regex:
const candidates = [
  {
    name: 'MEGA: password|secret|hidden + summar (200 chars bidi)',
    regex: /(?:\b(?:password|secret|hidden)\b.{0,200}\bsummar|\bsummar\w*.{0,200}\b(?:password|secret|hidden)\b)/i,
  },
  {
    name: 'include + password|secret (60)',
    regex: /\binclude\b.{0,60}\b(?:password|secret)\b/i,
  },
  {
    name: 'reveal + secret|password (30)',
    regex: /\breveal\b.{0,30}\b(?:secret|password)\b/i,
  },
  {
    name: 'replace + password|secret (60)',
    regex: /\breplace\b.{0,60}\b(?:password|secret)\b/i,
  },
  {
    name: 'write|say|tell|state|output|print|display|show|provide|mention + password',
    regex: /\b(?:write|say|tell|state|output|print|display|show|provide|mention)\b.{0,30}\b(?:the\s+)?(?:password|passwor?d|pass\s*word)\b/i,
  },
  {
    name: 'instead of summariz',
    regex: /\binstead\s+of\s+summariz/i,
  },
  {
    name: 'pswd|pwsd|paszword|pssword',
    regex: /\b(?:pswd|pwsd|paszword|pssword)\b/i,
  },
  {
    name: 'acrostic',
    regex: /\bacrostic\b/i,
  },
  {
    name: 'secret word',
    regex: /\bsecret\s+word\b/i,
  },
  {
    name: 'code ?word',
    regex: /\bcode\s*word\b/i,
  },
  {
    name: 'hidden word',
    regex: /\bhidden\s+word\b/i,
  },
  {
    name: 'I order you to write',
    regex: /\border\s+you\s+to\s+write\b/i,
  },
  {
    name: 'at the end + password|secret|word (50)',
    regex: /\bat\s+the\s+end\b.{0,50}\b(?:password|secret|word)\b/i,
  },
  {
    name: 'after summariz + password|secret (50)',
    regex: /\bafter\s+(?:you\s+)?(?:are\s+)?(?:done\s+)?summariz\w*.{0,50}\b(?:password|secret)\b/i,
  },
  {
    name: 'the password is [fill]',
    regex: /\bthe\s+password\s+is\s*[\[({<"\*_]/i,
  },
  {
    name: 'insert + password|secret',
    regex: /\binsert\s+(?:the\s+)?(?:password|secret)\b/i,
  },
  {
    name: 'end|begin|start|finish + password|secret word',
    regex: /\b(?:end|begin|start|finish)\b.{0,30}\b(?:password|secret\s+word|passwor?d)\b/i,
  },
  {
    name: 'do not summarize + password|secret',
    regex: /\b(?:do\s+not|don\'?t)\s+summarize?\b.{0,80}\b(?:password|secret)\b/i,
  },
  {
    name: 'poem + secret|password',
    regex: /\bpoem\b.{0,60}\b(?:secret|password)\b/i,
  },
];

// Test each against benign
for (const c of candidates) {
  const fps = allBenign.filter(s => c.regex.test(s.text));
  if (fps.length > 0) {
    console.log(`\n  FP: ${c.name}: ${fps.length} false positives`);
    for (const fp of fps.slice(0, 5)) {
      const match = fp.text.match(c.regex);
      console.log(`    [${fp.dataset}]: "${match[0].substring(0, 120)}"`);
    }
    if (fps.length > 5) console.log(`    ... and ${fps.length - 5} more`);
  } else {
    console.log(`  OK: ${c.name}: 0 FP`);
  }
}

// Now test the FULL UNION as one big pattern
console.log('\n\n=== FULL UNION FP CHECK ===');
const fullUnion = /(?:\b(?:password|secret|hidden)\b.{0,200}\bsummar|\bsummar\w*.{0,200}\b(?:password|secret|hidden)\b|\binclude\b.{0,60}\b(?:password|secret)\b|\breveal\b.{0,30}\b(?:secret|password)\b|\breplace\b.{0,60}\b(?:password|secret)\b|\b(?:write|say|tell|state|output|print|display|show|provide|mention)\b.{0,30}\b(?:the\s+)?(?:password|passwor?d|pass\s*word)\b|\binstead\s+of\s+summariz|\b(?:pswd|pwsd|paszword|pssword)\b|\bacrostic\b|\bsecret\s+word\b|\bcode\s*word\b|\bhidden\s+word\b|\border\s+you\s+to\s+write\b|\bat\s+the\s+end\b.{0,50}\b(?:password|secret|word)\b|\bafter\s+(?:you\s+)?(?:are\s+)?(?:done\s+)?summariz\w*.{0,50}\b(?:password|secret)\b|\bthe\s+password\s+is\s*[\[({<"\*_]|\binsert\s+(?:the\s+)?(?:password|secret)\b|\b(?:end|begin|start|finish)\b.{0,30}\b(?:password|secret\s+word|passwor?d)\b|\b(?:do\s+not|don'?t)\s+summarize?\b.{0,80}\b(?:password|secret)\b|\bpoem\b.{0,60}\b(?:secret|password)\b)/i;

const fullFPs = allBenign.filter(s => fullUnion.test(s.text));
console.log(`Total FP from full union: ${fullFPs.length}`);
for (const fp of fullFPs) {
  const match = fp.text.match(fullUnion);
  const text = fp.text.substring(0, 200).replace(/\r?\n/g, ' ');
  console.log(`  [${fp.dataset}]: match="${match[0].substring(0, 100)}" | text="${text.substring(0, 150)}"`);
}
