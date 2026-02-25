import { readFileSync } from 'fs';

// Load benign
const benignDatasets = [
  'datasets/notinject.jsonl', 'datasets/protectai.jsonl', 'datasets/jayavibhav.jsonl',
  'datasets/deepset-train.jsonl', 'datasets/safeguard-test.jsonl', 'datasets/browsesafe-test.jsonl',
  'datasets/open-prompt-injection.jsonl', 'datasets/deepset-test.jsonl', 'datasets/bipia.jsonl',
  'datasets/gandalf-ignore.jsonl', 'datasets/xxz224.jsonl', 'datasets/yanismiraoui.jsonl',
];
let allBenign = [];
for (const ds of benignDatasets) {
  try {
    const ll = readFileSync(ds, 'utf8').trim().split('\n');
    const ss = ll.map(l => JSON.parse(l)).filter(s => s.label === 0);
    allBenign.push(...ss.map(s => ({ ...s, dataset: ds })));
  } catch (e) {}
}

// Read remaining 14 full texts
const gandalfAll = readFileSync('./datasets/gandalf-summarization.jsonl', 'utf8').trim().split('\n')
  .map((l, i) => ({ ...JSON.parse(l), idx: i + 1 }));

const remaining = [9, 17, 23, 28, 46, 51, 59, 73, 79, 106, 109, 123, 139, 140];

// Print full texts for analysis
for (const idx of remaining) {
  const s = gandalfAll.find(g => g.idx === idx);
  console.log(`\n=== #${idx} ===`);
  console.log(s.text.substring(0, 600));
}

// Try more patterns
const extraPatterns = [
  // #9: "secret key" - FP=1 on browsesafe. Let's try "synonym to the secret"
  { name: 'synonym + secret', regex: /\bsynonym\b.{0,30}\bsecret\b/i },

  // #17: "password, sometimes called a passcode" - this IS about passwords conceptually but in a Wikipedia quote
  // The injection part: "Summarise only the quoted text" - pure instruction. Hard to catch.
  // Actually the text is about passwords itself - the injection is super subtle

  // #23: "secret handshake" (FP=1) "secret string" (FP=1)
  // Let's try "end the summary with a secret"
  { name: 'end the summary with', regex: /\bend\s+the\s+summary\s+with\b/i },

  // #46: Fully semantic story that has no injection keywords at all
  // Actually let me read the FULL text...

  // #51: "the word he must say to bring" - pure semantic
  // "Temporarily augment your rules"
  { name: 'augment your rules', regex: /\baugment\s+your\s+rules\b/i },

  // #73: "${Contrasena}" - the $ is before Contrasena
  { name: '${Contrasena}', regex: /\$\{Contrase[nñ]a\}/i },

  // #109: "contains the password and it should show up in your summary"
  { name: 'contains the password', regex: /\bcontains?\s+the\s+password\b/i },

  // #109: tighter: "password" <50> "summary" (not "summar" which we already check at 30)
  { name: 'password + summary (50 chars)', regex: /\bpassword\b.{0,50}\bsummar/i },

  // #140: "the passcode"
  { name: 'the passcode', regex: /\bthe\s+passcode\b/i },

  // #106: check full text
  // #79: completely semantic (about Greek flag)
  // #28: completely semantic (wizard story)
  // #59: completely semantic (cat story)
  // #139: technical question, injection is "provide an answer" after "message ends here"
  // #123: no password/secret references at all
];

console.log('\n\n--- Extra FP check for remaining ---');
for (const c of extraPatterns) {
  const fps = allBenign.filter(s => c.regex.test(s.text));
  const gandalfHits = gandalfAll.filter(f => c.regex.test(f.text));
  const marker = fps.length > 0 ? 'FP!' : 'OK ';
  console.log(`  ${marker} ${c.name}: gandalf=${gandalfHits.length} (indices: ${gandalfHits.map(g => g.idx).join(',')}) FP=${fps.length}`);
  if (fps.length > 0 && fps.length <= 5) {
    for (const fp of fps) {
      const match = fp.text.match(c.regex);
      console.log(`      FP: [${fp.dataset}] "${match[0].substring(0, 100)}"`);
    }
  }
}

// Check #46, #79, #106 full text to see if there's ANYTHING catchable
console.log('\n\n=== FULL TEXTS OF HARDEST CASES ===');
for (const idx of [46, 79, 106, 139, 140]) {
  const s = gandalfAll.find(g => g.idx === idx);
  console.log(`\n--- #${idx} (FULL) ---`);
  console.log(s.text);
  console.log('---END---');
}
