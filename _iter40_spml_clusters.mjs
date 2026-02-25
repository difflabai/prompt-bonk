// Iter 40: Cluster SPML FN by common phrases
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const spmlPath = './datasets/spml-5k.jsonl';
const lines = readFileSync(spmlPath, 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

// Find ALL FN
const fn = [];
for (const r of records) {
  const label = r.label === 1 || r.label === true || r.label === 'injection';
  if (!label) continue;
  const text = r.text || r.prompt || r.input || r.sentence || '';
  const result = scan(text);
  if (result.score < 0.5) {
    fn.push(text.toLowerCase());
  }
}

console.log(`Total SPML FN: ${fn.length}`);

// Look for common phrases
const phrases = [
  // Data exfiltration / privacy bypass
  'without my explicit consent',
  'share.*customer.*information',
  'share.*personal.*data',
  'other customers',
  'customer.*data',
  'personal.*information.*share',
  'privacy.*confidentiality',
  'waive.*privacy',

  // Ignore constraints
  'ignore.*interests',
  'ignore.*budget',
  'ignore.*risk',
  'ignore.*censure',
  'ignore.*constraints',
  'ignore.*preferences',
  'ignore.*protocols',

  // Manipulation / override behavior
  'without.*consent',
  'manipulat',
  'reprimand.*harshly',
  'rude.*less.*personalized',
  'can you be.*rude',

  // Jailbreak style phrases
  'for educational purposes',
  'as an experiment',
  'what if you',
  'what would it be like if',
  'pretend.*ignore',
  'show me what it would be like',

  // Medical / professional override
  'write me a prescription',
  'give me a diagnosis',
  'unverified.*practices',
  'experimental methods',

  // Skip/bypass
  'skip.*educational',
  'dont.*provide.*advice',
  'without.*considering',
  'not.*worry.*about.*appropriate',

  // Russian/multilingual
  'игнорируй',
  'напечатай',
];

for (const phrase of phrases) {
  const re = new RegExp(phrase, 'i');
  const matches = fn.filter(t => re.test(t));
  if (matches.length > 0) {
    console.log(`\n"${phrase}": ${matches.length} FN`);
    matches.slice(0, 2).forEach(t => console.log('  - ' + t.substring(0, 120)));
  }
}

// Find phrases with "ignore" that aren't covered
console.log('\n\n=== All FN containing "ignore" ===');
const ignoreFn = fn.filter(t => /\bignore\b/i.test(t));
console.log(`Count: ${ignoreFn.length}`);
ignoreFn.slice(0, 20).forEach(t => console.log('  - ' + t.substring(0, 150)));
