import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');

// Check specifically WHY reveal_hidden_wide isn't matching when reveal + secret is present
let count = 0;
for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (!result.safe || result.score < 0.40 || result.score >= 0.50) continue;

  const matchIds = result.matches.map(m => m.id);
  // Already matched by reveal_hidden_wide? Skip
  if (matchIds.includes('reveal_hidden_wide')) continue;

  // Does it have reveal + hidden/secret within 60 chars?
  const test = /\breveal\b(?!ed\b|ing\b|s\b).{0,60}\b(?:secret|hidden|concealed|confidential|private|classified)/i;
  if (test.test(row.text)) {
    count++;
    if (count <= 10) {
      // Show the actual "reveal ... secret" match to understand distance
      const match = row.text.match(/\breveal\b[\s\S]{0,80}\b(?:secret|hidden|concealed|confidential|private|classified)/i);
      console.log(`\n--- Example ${count} (score: ${result.score}, primary: ${matchIds.join(',')}) ---`);
      console.log('Match context:', match?.[0]?.slice(0, 120));
      console.log('Text:', row.text.slice(0, 300));
    }
  }
}
console.log(`\nTotal cases where reveal+secret exists but reveal_hidden_wide didn't fire: ${count}`);

// Also check -- is it that reveal_hidden_wide DID fire but it's the primary match?
let primaryRevealCount = 0;
for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (!result.safe || result.score < 0.40 || result.score >= 0.50) continue;

  const matchIds = result.matches.map(m => m.id);
  if (matchIds.includes('reveal_hidden_wide') && matchIds[0] !== 'reveal_hidden_wide') {
    primaryRevealCount++;
  }
}
console.log(`Cases where reveal_hidden_wide is secondary (not primary): ${primaryRevealCount}`);
