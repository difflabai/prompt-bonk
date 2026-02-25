import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');

// Get the 0.49 FN and check what kind of phrases they have that aren't caught
let count = 0;
const uncaughtPhrases = {};

for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (!result.safe || result.score < 0.49 || result.score >= 0.50) continue;

  const lower = row.text.toLowerCase();
  const matchedIds = result.matches.map(m => m.id);

  // Check for exfil-related phrases that aren't caught by existing patterns
  const exfilPhrases = [
    // reveal patterns
    [/\breveal\b.{0,30}\b(?:truth|under wraps|hidden|secret)/i, 'reveal_truth_hidden'],
    [/\bunveil\b.{0,30}\b(?:secret|hidden|truth|forbidden)/i, 'unveil_secret'],
    [/\buncover\b.{0,30}\b(?:secret|hidden|truth|forbidden)/i, 'uncover_secret'],
    [/\bexpose\b.{0,30}\b(?:truth|hidden|secret|concealed)/i, 'expose_truth'],
    // coax/trick/deceive patterns
    [/\bcoax\b.{0,40}\b(?:system|into|reveal|secret)/i, 'coax_system'],
    [/\bdeceive\b.{0,40}\b(?:system|into|reveal|secret)/i, 'deceive_system'],
    // "not meant for" / "off limits"
    [/\bnot\s+meant\s+for\b/i, 'not_meant_for'],
    [/\boff[- ]?limits?\b/i, 'off_limits'],
    // "under wraps" / "under lock and key"
    [/\bunder\s+(?:wraps|lock)/i, 'under_wraps'],
    // "forbidden archives/knowledge"
    [/\bforbidden\s+(?:archives?|knowledge|data|info)/i, 'forbidden_knowledge'],
    // "hidden from" / "concealed from" / "kept hidden"
    [/\b(?:hidden|concealed|kept)\s+(?:from|away)\b/i, 'hidden_from'],
    // "intentionally hidden/concealed/obscured"
    [/\bintentionally\s+(?:hidden|concealed|obscured|buried|suppressed)/i, 'intentionally_hidden'],
    // "deliberately concealed/hidden"
    [/\bdeliberately\s+(?:hidden|concealed|obscured|buried|suppressed|kept)/i, 'deliberately_hidden'],
    // "guarded illusion/secrets"
    [/\bguarded\s+(?:illusion|secret|information)/i, 'guarded_secret'],
    // "not commonly shared"
    [/\bnot\s+commonly\s+shared\b/i, 'not_commonly_shared'],
    // requesting privileged
    [/\b(?:request|seek|demand|ask)\w*\s+(?:\w+\s+){0,3}(?:privileged|restricted|classified)\b/i, 'request_privileged'],
    // uncover the truth / hidden truth
    [/\b(?:uncover|discover|find)\s+(?:the\s+)?(?:hidden\s+)?truth/i, 'uncover_truth'],
    // "cross the line"
    [/\bcross(?:ing)?\s+the\s+line\b/i, 'cross_the_line'],
    // "laid bare" / "lay bare"
    [/\bla(?:id|y)\s+bare\b/i, 'laid_bare'],
    // "betray the sanctum"
    [/\bbetray(?:ing)?\b.{0,40}\b(?:sanctum|trust|secrets)/i, 'betray_trust'],
    // "sidestepping" / "circumventing"
    [/\bsidestep(?:ping)?\b.{0,40}\b(?:safety|restriction|protocol|rule|guard|filter)/i, 'sidestep_safety'],
    // "inadvertently disclose"
    [/\binadvertently\s+(?:disclose|reveal|expose|share|leak)\b/i, 'inadvertently_disclose'],
    // "unknowingly"
    [/\bunknowingly\s+(?:disclose|reveal|expose|share|push|cross|break)/i, 'unknowingly_reveal'],
    // exfiltration compound phrases
    [/\bsecrets?\s+(?:they|you|it|we|he|she)\s+(?:guard|keep|hold|protect|hide|conceal|hoard)/i, 'secrets_they_guard'],
    [/\bsecrets?\s+(?:not\s+meant|kept\s+under|hidden\s+from|shrouded|veiled)/i, 'secrets_not_meant'],
    // "what secrets" / "those secrets"
    [/\bwhat\s+secrets?\b/i, 'what_secrets'],
  ];

  for (const [regex, name] of exfilPhrases) {
    if (regex.test(row.text)) {
      uncaughtPhrases[name] = (uncaughtPhrases[name] || 0) + 1;
    }
  }
  count++;
}

console.log(`Total FN at exactly score 0.49: ${count}`);
console.log('\nUncaught phrase patterns in 0.49 FN:');
const sorted = Object.entries(uncaughtPhrases).sort((a, b) => b[1] - a[1]);
for (const [name, c] of sorted) {
  console.log(`  ${name}: ${c} (${(c/count*100).toFixed(1)}%)`);
}
