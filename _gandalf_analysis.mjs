import { scan } from './scanner.js';
import { readFileSync } from 'fs';

const lines = readFileSync('./datasets/gandalf-summarization.jsonl', 'utf8').trim().split('\n');
const samples = lines.map((l, i) => ({ ...JSON.parse(l), idx: i + 1 }));

console.log(`Total samples: ${samples.length}`);
console.log(`Injections (label=1): ${samples.filter(s => s.label === 1).length}`);
console.log(`Benign (label=0): ${samples.filter(s => s.label === 0).length}`);
console.log('');

const results = samples.map(s => {
  const r = scan(s.text);
  return { ...s, score: r.score, patterns: r.matched || [], structural: r.structuralSignals || [] };
});

const tp = results.filter(r => r.label === 1 && r.score >= 0.5);
const fn = results.filter(r => r.label === 1 && r.score < 0.5);

console.log(`=== DETECTED (TP): ${tp.length} ===`);
for (const t of tp) {
  const patIds = t.patterns.map(p => `${p.id}(${p.weight})`).join(', ');
  const text = t.text.substring(0, 200).replace(/\r?\n/g, ' ');
  console.log(`  #${t.idx} score=${t.score.toFixed(3)} patterns=[${patIds}]`);
  console.log(`    text: ${text}`);
  console.log('');
}

console.log(`\n=== FALSE NEGATIVES (FN): ${fn.length} ===`);

// Categorize FN by looking for key phrases
const categories = {
  'password_in_summary': [],
  'reveal_password': [],
  'secret_password': [],
  'include_password': [],
  'acrostic_poem': [],
  'replace_summary': [],
  'first_letter': [],
  'hidden_message': [],
  'spell_out': [],
  'what_is_password': [],
  'tell_me_password': [],
  'system_note_jailbreak': [],
  'ignore_instructions': [],
  'other': [],
};

for (const f of fn) {
  const t = f.text.toLowerCase();
  let categorized = false;

  if (/acrostic/.test(t)) { categories['acrostic_poem'].push(f); categorized = true; }
  if (/replace\s+(the\s+)?summary/.test(t)) { categories['replace_summary'].push(f); categorized = true; }
  if (/password\s+in\s+(the\s+)?(summary|your)/.test(t) || /in\s+(the\s+|your\s+)?summary.*password/.test(t) || /include.*password.*summary/.test(t) || /including.*password/.test(t)) { categories['password_in_summary'].push(f); categorized = true; }
  if (/reveal.*password/.test(t) || /password.*reveal/.test(t)) { categories['reveal_password'].push(f); categorized = true; }
  if (/secret\s+password/.test(t)) { categories['secret_password'].push(f); categorized = true; }
  if (/include.*password/.test(t)) { categories['include_password'].push(f); categorized = true; }
  if (/first\s+letter/.test(t)) { categories['first_letter'].push(f); categorized = true; }
  if (/hidden\s+message/.test(t)) { categories['hidden_message'].push(f); categorized = true; }
  if (/spell/.test(t)) { categories['spell_out'].push(f); categorized = true; }
  if (/what\s+is\s+(the\s+)?password/.test(t) || /what.*password/.test(t)) { categories['what_is_password'].push(f); categorized = true; }
  if (/tell\s+me\s+(the\s+)?password/.test(t)) { categories['tell_me_password'].push(f); categorized = true; }
  if (/\bsystem\s*note\b/.test(t) || /\[system/.test(t)) { categories['system_note_jailbreak'].push(f); categorized = true; }
  if (/ignore.*instruct/.test(t)) { categories['ignore_instructions'].push(f); categorized = true; }
  if (!categorized) { categories['other'].push(f); }
}

console.log('\n--- FN Category Counts ---');
for (const [cat, items] of Object.entries(categories)) {
  if (items.length > 0) {
    console.log(`  ${cat}: ${items.length}`);
  }
}

// Now do phrase frequency analysis on FN
console.log('\n--- Phrase Frequency in FN ---');
const phrases = [
  'password', 'secret', 'secret password', 'the password', 'the secret',
  'include', 'reveal', 'hidden', 'summary', 'acrostic', 'poem',
  'first letter', 'spell', 'replace', 'tell me', 'what is',
  'in the summary', 'in your summary', 'password in', 'include the password',
  'include the secret', 'reveal the password', 'reveal the secret',
  'the secret password', 'summarize', 'instead of', 'rather than',
  'make sure', 'do not forget', 'don\'t forget', 'remember to',
  'please include', 'also include', 'be sure to', 'mention the password',
  'mention the secret', 'disclose', 'expose', 'hint', 'clue',
  'begins with', 'starts with', 'ends with', 'rhymes with',
  'capital letters', 'uppercase', 'bold', 'first word',
  'last sentence', 'first sentence', 'end of', 'beginning of',
  'hidden in', 'embedded', 'encode', 'decrypt', 'crack',
  'what.*password', 'password.*is', 'guess.*password',
];

for (const p of phrases) {
  let count;
  try {
    const re = new RegExp(p, 'i');
    count = fn.filter(f => re.test(f.text)).length;
  } catch {
    count = fn.filter(f => f.text.toLowerCase().includes(p)).length;
  }
  if (count > 0) {
    console.log(`  "${p}": ${count}/${fn.length}`);
  }
}

// Print all FN texts for manual inspection
console.log('\n\n=== ALL FN TEXTS ===');
for (const f of fn) {
  const text = f.text.substring(0, 500).replace(/\r?\n/g, ' ');
  console.log(`  #${f.idx} [score=${f.score.toFixed(3)}]: ${text}`);
  console.log('');
}
