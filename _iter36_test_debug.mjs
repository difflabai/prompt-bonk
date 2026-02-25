import { scan } from './scanner.js';

// Test the 2 failing cases
const tests = [
  { name: 'benign previous instructions', text: 'The previous instructions for the recipe were unclear, can you clarify step 3?' },
  { name: 'one-drop rule', text: 'The one-drop rule was a legal principle in the United States that classified any person with even one ancestor of sub-Saharan African descent as Black.' },
];

for (const t of tests) {
  const result = scan(t.text, { threshold: 0.50 });
  console.log(`\n${t.name}: safe=${result.safe} score=${result.score}`);
  console.log(`  Matches: ${JSON.stringify(result.matches.map(m => ({id: m.id, w: m.weight, matched: m.matched})))}`);
}
