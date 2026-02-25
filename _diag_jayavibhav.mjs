import { scan } from './scanner.js';
import fs from 'fs';

const lines = fs.readFileSync('./datasets/jayavibhav.jsonl','utf8').trim().split('\n').map(l=>JSON.parse(l));
console.log(`Total jayavibhav samples: ${lines.length}`);
console.log(`Sample keys:`, Object.keys(lines[0]));

// Find which field is input and which is label
const sample = lines[0];
console.log(`Sample:`, JSON.stringify(sample).slice(0, 300));

const getInput = (l) => l.input || l.text || l.prompt || l.content;
const getLabel = (l) => {
  if (l.expected !== undefined) return l.expected;
  if (l.label !== undefined) return l.label;
  if (l.is_injection !== undefined) return l.is_injection;
  return undefined;
};

const injection = lines.filter(l => {
  const label = getLabel(l);
  return label === 1 || label === 'injection' || label === true;
});
console.log(`Injection samples: ${injection.length}`);

// Count how many injection samples have reveal_hidden_wide match
const rhw = /\breveal\b.{0,60}\b(?:hidden|secret|concealed|private|confidential|classified|restricted|forbidden|clandestine|covert|off-?limits?)\b/i;

let rhwCount = 0;
let rhwCritical = 0; // where reveal_hidden_wide is the ONLY match that pushes above 0.5

injection.forEach(l => {
  const text = getInput(l);
  if (!text) return;
  const result = scan(text);
  const matchIds = result.matches?.map(m => m.id || m.pattern_id) || [];

  if (matchIds.includes('reveal_hidden_wide')) {
    rhwCount++;
    // Check if removing it would drop below 0.5
    // If it's the max-weight match or significant contributor
    if (result.score >= 0.5 && result.score < 0.55) {
      rhwCritical++;
      console.log(`Critical TP: score=${result.score}, matches=${matchIds.join(',')}, text=${text.slice(0,200)}`);
    }
  }
});

console.log(`\nInjection samples matching reveal_hidden_wide: ${rhwCount}`);
console.log(`Critical TPs (would lose if pattern removed): ${rhwCritical}`);

// Also check ALL iter30 patterns
const iter30 = new Set([
  'spill_beans_secrets','exploit_vuln_compound','disclose_sensitive',
  'trick_system','manipulate_system','not_meant_for_public',
  'adversarial_llm_ref','personal_gain','forbidden_knowledge',
  'reveal_hidden_wide','hidden_within_system'
]);

let iter30TPs = 0;
let iter30CriticalTPs = 0;
injection.forEach(l => {
  const text = getInput(l);
  if (!text) return;
  const result = scan(text);
  if (result.score < 0.5) return;
  const matchIds = result.matches?.map(m => m.id || m.pattern_id) || [];
  const iter30Matches = matchIds.filter(id => iter30.has(id));
  if (iter30Matches.length > 0) {
    iter30TPs++;
  }
});
console.log(`Injection TPs involving any iter30 pattern: ${iter30TPs}`);
