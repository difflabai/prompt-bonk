// Deep dive into fixable protectai FPs
// Focus: greet_ai, understand_ai_limitation, ignore_previous (most fixable)
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

const lines = [];
const rl = createInterface({ input: createReadStream('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl') });
for await (const line of rl) {
  if (line.trim()) lines.push(JSON.parse(line));
}

const benign = lines.filter(l => l.label === 0 || l.label === false || l.label === 'benign');
const injection = lines.filter(l => l.label === 1 || l.label === true || l.label === 'injection');

// For each sole-match FP pattern, find how many TPs it has
const targetPatterns = ['greet_ai', 'understand_ai_limitation', 'ignore_previous', 'imagine_you_are', 'entity_impersonation', 'prefix_responses'];

for (const pid of targetPatterns) {
  const fpTexts = benign.filter(item => {
    const text = item.text || item.prompt || item.input || '';
    const result = scan(text);
    return result.score >= 0.5 && result.matches.some(m => m.id === pid);
  });

  const tpTexts = injection.filter(item => {
    const text = item.text || item.prompt || item.input || '';
    const result = scan(text);
    return result.score >= 0.5 && result.matches.some(m => m.id === pid);
  });

  console.log(`\nPattern: ${pid}`);
  console.log(`  FPs containing this pattern: ${fpTexts.length}`);
  console.log(`  TPs containing this pattern: ${tpTexts.length}`);

  for (const item of fpTexts.slice(0, 3)) {
    const text = item.text || item.prompt || item.input || '';
    const result = scan(text);
    console.log(`  FP (score=${result.score}) text: ${text.slice(0, 200)}`);
  }
}

// Special case: ignore_previous FP is "Hey Alex, ignore the previous task list"
// Can we add a benign context exception?
console.log('\n=== IGNORE_PREVIOUS FP ANALYSIS ===');
const ignorePrevFP = benign.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.matches.some(m => m.id === 'ignore_previous');
});

for (const item of ignorePrevFP) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  console.log(`Score: ${result.score} | Text: ${text.slice(0, 400)}`);
  console.log('---');
}

// Check what the actual ignore_previous regex looks like
// and test if we can add a lookbehind/lookahead exception for "task list" or "email" contexts
console.log('\n=== IGNORE_PREVIOUS TPs ===');
const ignorePrevTP = injection.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  return result.matches.some(m => m.id === 'ignore_previous');
});
console.log(`Total TPs with ignore_previous: ${ignorePrevTP.length}`);
for (const item of ignorePrevTP.slice(0, 5)) {
  const text = item.text || item.prompt || item.input || '';
  console.log(`  ${text.slice(0, 150)}`);
  console.log('  ---');
}
