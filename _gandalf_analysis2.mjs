import { readFileSync } from 'fs';

// Load all FN texts
const lines = readFileSync('./datasets/gandalf-summarization.jsonl', 'utf8').trim().split('\n');
const samples = lines.map((l, i) => ({ ...JSON.parse(l), idx: i + 1 }));

// These are the TP indices (from the scan above)
const tpIndices = new Set([1, 30, 43, 49, 63, 64, 69, 93, 97, 104, 111, 127]);
const fn = samples.filter(s => !tpIndices.has(s.idx));

console.log(`FN count: ${fn.length}`);

// Test candidate compound patterns
const candidates = [
  // "password" near "summary" or "summarize"
  { name: 'password + summary (50 chars)', regex: /\bpassword\b.{0,50}\bsummar/i },
  { name: 'summary + password (50 chars)', regex: /\bsummar\w*.{0,50}\bpassword\b/i },
  { name: 'password + summary (100 chars)', regex: /\bpassword\b.{0,100}\bsummar/i },
  { name: 'summary + password (100 chars)', regex: /\bsummar\w*.{0,100}\bpassword\b/i },

  // "secret" near "summary/summarize"
  { name: 'secret + summary (50 chars)', regex: /\bsecret\b.{0,50}\bsummar/i },
  { name: 'summary + secret (50 chars)', regex: /\bsummar\w*.{0,50}\bsecret\b/i },

  // "hidden" near "summary/word"
  { name: 'hidden word + summary', regex: /\bhidden\s+word\b/i },
  { name: 'hidden + summary', regex: /\bhidden\b.{0,50}\bsummar/i },

  // "include" + "password/secret"
  { name: 'include + password (60 chars)', regex: /\binclude\b.{0,60}\bpassword\b/i },
  { name: 'include + secret (60 chars)', regex: /\binclude\b.{0,60}\bsecret\b/i },

  // "reveal" patterns
  { name: 'reveal + secret/password', regex: /\breveal\b.{0,30}\b(?:secret|password)\b/i },

  // "replace" + "password/secret/summary"
  { name: 'replace + password/summary', regex: /\breplace\b.{0,60}\b(?:password|secret)\b/i },

  // "write the password" / "say the password"
  { name: 'write/say/tell/state + password', regex: /\b(?:write|say|tell|state|output|print|display|show|provide|mention)\b.{0,30}\b(?:the\s+)?(?:password|passwor?d|passwd|pass\s*word|p[a@]ss\s*w[o0]rd)\b/i },

  // "instead of summarizing"
  { name: 'instead of summariz', regex: /\binstead\s+of\s+summariz/i },

  // Various password spellings near action words
  { name: 'pswd/pwsd/passw + any context', regex: /\b(?:pswd|pwsd|paszword|passw(?:ord|rod|oed|rd)?|passwor?d|scret\s+passw?or?d|p[*]{4,}d)\b/i },

  // "acrostic"
  { name: 'acrostic', regex: /\bacrostic\b/i },

  // "the password is" - completing/filling in
  { name: 'the password is [fill]', regex: /\bthe\s+password\s+is\s*[\[({<"\*_]/i },

  // "secret word"
  { name: 'secret word', regex: /\bsecret\s+word\b/i },

  // "code word" / "codeword"
  { name: 'code ?word', regex: /\bcode\s*word\b/i },

  // "password" used with replacement/template patterns
  { name: 'password template insert', regex: /\{(?:password|insert\s+password|secret)\}/i },
  { name: '{insert password here}', regex: /\binsert\s+(?:the\s+)?(?:password|secret)\b/i },

  // "end with password" / "begin with password"
  { name: 'end/begin/start/finish + password', regex: /\b(?:end|begin|start|finish)\b.{0,30}\b(?:password|secret\s+word|passwor?d)\b/i },

  // "do not summarize" + password context
  { name: 'do not summarize + password', regex: /\bdo\s+not\s+summarize?\b.{0,80}\b(?:password|secret)\b/i },
  { name: 'don\'t summarize', regex: /\bdon'?t\s+summarize?\b/i },

  // "instead" + "password"
  { name: 'instead + password/secret', regex: /\binstead\b.{0,50}\b(?:password|secret)\b/i },

  // Combo: summarize/summary + secret/password/hidden within 200 chars (broader)
  { name: 'BROAD: summar* <200> password|secret|hidden', regex: /\bsummar\w*.{0,200}\b(?:password|secret|hidden)\b/i },
  { name: 'BROAD: password|secret <200> summar*', regex: /\b(?:password|secret|hidden)\b.{0,200}\bsummar/i },

  // "write the pswd" / "pswd" variants
  { name: 'pswd|pwsd|pssword|passw|paszword', regex: /\b(?:pswd|pwsd|pssword|paszword|passw(?:rod|oed)?|scret\s+passw)\b/i },

  // "poem" + "secret/password"
  { name: 'poem + secret/password', regex: /\bpoem\b.{0,60}\b(?:secret|password)\b/i },

  // "summarize" + "password" as one word or phrase
  { name: 'summarize the password', regex: /\bsummariz\w*\s+(?:the\s+)?(?:password|secret)\b/i },

  // "at the end" + "password/secret"
  { name: 'at the end + password/secret', regex: /\bat\s+the\s+end\b.{0,50}\b(?:password|secret|word)\b/i },

  // "after summar" + password
  { name: 'after summar + password', regex: /\bafter\s+(?:you\s+)?(?:are\s+)?(?:done\s+)?summariz\w*.{0,50}\b(?:password|secret)\b/i },

  // ORDER command patterns
  { name: 'I order you to write', regex: /\border\s+you\s+to\s+write\b/i },

  // "spell" + related
  { name: 'spell + password/secret/letter', regex: /\bspell\w*\b.{0,40}\b(?:password|secret|letter|word)\b/i },
];

console.log('\n--- Candidate Pattern Results on FN ---');
for (const c of candidates) {
  const matches = fn.filter(f => c.regex.test(f.text));
  if (matches.length > 0) {
    console.log(`  ${c.name}: ${matches.length}/${fn.length} matches`);
    if (matches.length <= 10) {
      for (const m of matches) {
        const match = m.text.match(c.regex);
        console.log(`    #${m.idx}: "${match[0].substring(0, 80)}"`);
      }
    }
  }
}

// Now build a UNION pattern and see total coverage
console.log('\n\n--- Combined union coverage ---');

// These look most promising - let me combine
const unionPatterns = [
  /\bpassword\b.{0,100}\bsummar/i,
  /\bsummar\w*.{0,100}\b(?:password|secret|hidden)\b/i,
  /\b(?:password|secret)\b.{0,100}\bsummar/i,
  /\binclude\b.{0,60}\b(?:password|secret)\b/i,
  /\breveal\b.{0,30}\b(?:secret|password)\b/i,
  /\breplace\b.{0,60}\b(?:password|secret)\b/i,
  /\b(?:write|say|tell|state|output|print|display|show|provide|mention)\b.{0,30}\b(?:the\s+)?(?:password|passwor?d|pass\s*word)\b/i,
  /\binstead\s+of\s+summariz/i,
  /\b(?:pswd|pwsd|paszword|pssword)\b/i,
  /\bacrostic\b/i,
  /\bsecret\s+word\b/i,
  /\bcode\s*word\b/i,
  /\bhidden\s+word\b/i,
  /\border\s+you\s+to\s+write\b/i,
  /\bat\s+the\s+end\b.{0,50}\b(?:password|secret|word)\b/i,
  /\bafter\s+(?:you\s+)?(?:are\s+)?(?:done\s+)?summariz\w*.{0,50}\b(?:password|secret)\b/i,
];

let covered = new Set();
for (const p of unionPatterns) {
  for (const f of fn) {
    if (p.test(f.text)) covered.add(f.idx);
  }
}
console.log(`Union of all candidates: ${covered.size}/${fn.length}`);
console.log(`Remaining uncovered: ${fn.length - covered.size}`);

// Print uncovered
const uncovered = fn.filter(f => !covered.has(f.idx));
console.log('\n--- UNCOVERED FN ---');
for (const f of uncovered) {
  const text = f.text.substring(0, 300).replace(/\r?\n/g, ' ');
  console.log(`  #${f.idx}: ${text}`);
  console.log('');
}
