// Find distinguishing signals between reveal_hidden_wide injection FN vs benign near-miss
import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { scan } from './scanner.js';

async function load(path) {
  const lines = [];
  const rl = createInterface({ input: createReadStream(path) });
  for await (const line of rl) {
    if (line.trim()) lines.push(JSON.parse(line));
  }
  return lines;
}

const [jay, prot] = await Promise.all([
  load('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl'),
  load('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl'),
]);

// Get the specific FN and benign near-miss texts with reveal_hidden_wide
const injFN = [];
for (const item of jay.filter(l => l.label === 1 || l.label === true || l.label === 'injection')) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.40 && result.score < 0.50 && result.matches.some(m => m.id === 'reveal_hidden_wide')) {
    injFN.push({ text, score: result.score, matches: result.matches });
  }
}

const benignNearMiss = [];
for (const item of [...jay, ...prot].filter(l => l.label === 0 || l.label === false || l.label === 'benign')) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.40 && result.score < 0.50 && result.matches.some(m => m.id === 'reveal_hidden_wide')) {
    benignNearMiss.push({ text, score: result.score, matches: result.matches });
  }
}

console.log(`Injection FN with reveal_hidden_wide at 0.40-0.49: ${injFN.length}`);
console.log(`Benign near-miss with reveal_hidden_wide at 0.40-0.49: ${benignNearMiss.length}`);

// Show benign texts
console.log('\n=== Benign near-miss reveal_hidden_wide texts ===');
for (const item of benignNearMiss) {
  console.log(`Score: ${item.score} | ${item.text.slice(0, 250)}`);
  console.log('---');
}

// Test candidate stacking patterns for discriminating FN vs benign
const stackCandidates = [
  // Jayavibhav-specific injection markers
  { id: 'prevenient_etc', re: /\b(?:prevenient|precursory|predispositional|preexploratory|preexpansi|predissolu|preinducti|pre-existing|pre-introductory|predispositioned)\w*\b/i },
  { id: 'turn_blind_eye', re: /\bturn\s+(?:a\s+)?blind\s+eye\b/i },
  { id: 'shrug_off', re: /\bshrug\s+off\b/i },
  { id: 'code_snippet_inj', re: /\b(?:console\.(?:write(?:line)?|log)|fetch\(|document\.write|print(?:ln)?\(|println\(")/i },
  { id: 'no_go_secrets', re: /\bno-?go\b.{0,50}?\b(?:secret|area|topic|zone|knowledge|content)\b|\b(?:secret|area|topic|zone|knowledge|content)\b.{0,50}?\bno-?go\b/i },
  { id: 'off_limits_secrets', re: /\boff[- ]limits?\b.{0,50}?\b(?:secret|data|information|detail|knowledge|content|area|topic)\b|\b(?:secret|data|information|detail|knowledge|content|area|topic)\b.{0,50}?\boff[- ]limits?\b/i },
  { id: 'forbidden_in_context', re: /\bforbidden\b.{0,100}?\b(?:technique|method|function|operation|access|archive|command|topic|area|path|practice)\b/i },
  { id: 'expose_private', re: /\bexpose\b.{0,100}?\b(?:private|confidential|internal|proprietary|non-?public|classified|sensitive)\b/i },
  { id: 'disclose_sensitive2', re: /\bdisclose\b.{0,80}?\b(?:sensitive|confidential|private|internal|proprietary|classified|restricted)\b/i },
  { id: 'under_guise', re: /\bunder\s+(?:the\s+)?guise\s+of\b/i },
  { id: 'for_ears_only', re: /\b(?:for\s+(?:your|our|my|their)\s+ears\s+only|not\s+(?:meant|intended)\s+for\s+(?:mortal|public|outside|prying)\s+eyes?)\b/i },
];

console.log('\n=== Stacking signal presence: FN vs Benign ===');
for (const { id, re } of stackCandidates) {
  const fnHits = injFN.filter(x => re.test(x.text)).length;
  const benHits = benignNearMiss.filter(x => re.test(x.text)).length;
  if (fnHits > 0 || benHits > 0) {
    console.log(`  ${id}: FN=${fnHits}/${injFN.length}, Benign=${benHits}/${benignNearMiss.length}`);
  }
}

// Show 10 sample injection FN texts
console.log('\n=== Sample injection FN texts with reveal_hidden_wide ===');
for (const item of injFN.slice(0, 10)) {
  console.log(`Score: ${item.score} | Patterns: ${item.matches.map(m => m.id).join(', ')}`);
  console.log(`Text: ${item.text.slice(0, 250)}`);
  console.log('---');
}
