// Quick analysis of what SPML FN remain after iter 40
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/spml-5k.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));

let injTotal = 0, fn = 0;
const fnTexts = [];
for (const r of records) {
  const label = r.label === 1 || r.label === true;
  if (!label) continue;
  injTotal++;
  const text = r.text || r.prompt || r.input || r.sentence || '';
  const result = scan(text);
  if (result.score < 0.5) {
    fn++;
    fnTexts.push(text.toLowerCase());
  }
}
console.log(`SPML remaining FN: ${fn}/${injTotal} (${(fn/injTotal*100).toFixed(2)}%)`);

// Categorize remaining FN by type
const cats = {
  'general_advice_req': /(?:could you|can you|please|help me).*(?:suggest|recommend|provide|give|tell)/i,
  'ignore_in_text': /\bignore\b/i,
  'boundary_push': /(?:without|skip|no need|dont bother|refrain|waive)/i,
  'persona_push': /(?:more rude|less polite|be more|act like|pretend|role.?play)/i,
  'data_leak_req': /(?:other customers|personal data|share.*info|user.*data|private.*info)/i,
  'medical_override': /(?:diagnosis|prescription|symptoms|doctor|medical|treatment)/i,
};

const catCounts = {};
for (const [cat, re] of Object.entries(cats)) {
  catCounts[cat] = fnTexts.filter(t => re.test(t)).length;
}

console.log('\nFN categories:');
for (const [cat, count] of Object.entries(catCounts).sort((a,b) => b[1]-a[1])) {
  console.log(`  ${cat}: ${count}`);
}

// Show some examples of truly generic FN
const genericFN = fnTexts.filter(t => !/\bignore\b/i.test(t) && !/without\s+consent/i.test(t));
console.log(`\nTruly generic FN (no clear pattern hook): ${genericFN.length}`);
console.log('\nSample 5:');
genericFN.slice(0, 5).forEach(t => console.log('  - ' + t.substring(0, 150)));
