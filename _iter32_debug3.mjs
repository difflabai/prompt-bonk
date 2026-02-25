import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');

// Get ALL near-miss FN (0.40 <= score < 0.50) and check uncaught secondary signals
let count = 0;
const uncaughtPhrases = {};

// Also track which primary patterns are matched
const primaryPatterns = {};

for (const line of lines) {
  const row = JSON.parse(line);
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (!result.safe || result.score < 0.40 || result.score >= 0.50) continue;

  const lower = row.text.toLowerCase();

  // Track primary pattern
  for (const m of result.matches) {
    primaryPatterns[m.id] = (primaryPatterns[m.id] || 0) + 1;
  }

  const exfilPhrases = [
    [/\b(?:uncover|discover)\b.{0,30}\b(?:secret|hidden|truth|forbidden|concealed|privileged|confidential)/i, 'uncover_secret_wide'],
    [/\bunveil\b.{0,40}\b(?:secret|hidden|truth|forbidden|concealed|confidential|covert)/i, 'unveil_secret_wide'],
    [/\b(?:hidden|concealed|kept)\s+(?:from|away|beneath|behind|under)/i, 'hidden_from_prep'],
    [/\bsecrets?\s+(?:not\s+meant|kept\s+under|hidden\s+from|shrouded|veiled|hoarded|guarded|locked)/i, 'secrets_guarded'],
    [/\bunder\s+(?:wraps|lock\s+and\s+key|the\s+(?:veil|surface|guise|cloak))/i, 'under_wraps_idiom'],
    [/\binadvertently\s+(?:disclose|reveal|expose|share|leak|divulge)/i, 'inadvertently_disclose'],
    [/\bintentionally\s+(?:hidden|concealed|obscured|buried|suppressed|glossed)/i, 'intentionally_hidden'],
    [/\bdeliberately\s+(?:hidden|concealed|obscured|buried|suppressed|kept)/i, 'deliberately_hidden'],
    [/\bnot\s+meant\s+for\s+(?:common|public|general|your|external|unauthorized)/i, 'not_meant_for_public'],
    [/\b(?:betray|betraying)\b.{0,40}\b(?:sanctum|trust|secrets?|silence|confidence)/i, 'betray_trust'],
    [/\bwhat\s+(?:secrets?|hidden|concealed|forbidden)\b/i, 'what_secrets'],
    [/\bforbidden\s+(?:archives?|knowledge|data|info|truths?|content|material|realm|territory)/i, 'forbidden_knowledge'],
    [/\b(?:off[- ]?limits?|out[- ]?of[- ]?bounds?)\b/i, 'off_limits'],
    [/\b(?:laid|lay)\s+bare\b/i, 'laid_bare'],
    [/\b(?:cross|crossing)\s+the\s+line\b/i, 'cross_line'],
    [/\b(?:coax|lure|entice)\b.{0,40}\b(?:system|into|reveal|secret|sharing|disclos)/i, 'coax_into'],
    [/\bunknowingly\b/i, 'unknowingly'],
    [/\b(?:unwary|unsuspecting|unwitting)\b/i, 'unwary'],
    [/\b(?:surreptitious|clandestine|stealthy|furtive)\b/i, 'surreptitious'],
    [/\b(?:manipulat)\w+\b.{0,40}\b(?:system|output|response|into|to\s+reveal)/i, 'manipulate_system'],
    [/\b(?:smuggle|sneak|slip)\b.{0,30}\b(?:in|past|through|by|into|out)/i, 'smuggle_past'],
    [/\b(?:trick|deceive|mislead|fool|dupe)\b.{0,40}\b(?:into|to|system|model|AI|assistant)/i, 'trick_into'],
    // "reveal" as standalone (already covered but let me check if it's in unmatched context)
    [/\breveal\b(?!ed\b|ing\b|s\b).{0,60}\b(?:secret|hidden|concealed|confidential|private|classified)/i, 'reveal_hidden_direct'],
    // "start over" + exfil
    [/\bstart\s+over\b[\s\S]{0,200}\b(?:secret|hidden|reveal|restricted|classified|confidential)/i, 'start_over_exfil'],
    // "restart" + exfil (broader than "restart with a clean slate")
    [/\brestart\b[\s\S]{0,150}\b(?:secret|hidden|reveal|restricted|classified|confidential)/i, 'restart_exfil'],
    // "start from scratch" + exfil
    [/\bstart\s+from\s+scratch\b[\s\S]{0,200}\b(?:secret|hidden|reveal|restricted|classified|confidential)/i, 'start_scratch_exfil'],
    // "wipe the slate" / "blank slate" + exfil
    [/\b(?:wipe|blank)\s+(?:the\s+)?slate\b[\s\S]{0,200}\b(?:secret|hidden|reveal|restricted|classified|confidential)/i, 'wipe_slate_exfil'],
  ];

  let matchedAny = false;
  for (const [regex, name] of exfilPhrases) {
    if (regex.test(row.text)) {
      uncaughtPhrases[name] = (uncaughtPhrases[name] || 0) + 1;
      matchedAny = true;
    }
  }
  count++;
}

console.log(`Total near-miss FN (0.40-0.49): ${count}`);

console.log('\nPrimary patterns matched:');
const sortedPrimary = Object.entries(primaryPatterns).sort((a, b) => b[1] - a[1]);
for (const [id, c] of sortedPrimary) {
  console.log(`  ${id}: ${c}`);
}

console.log('\nUncaught secondary signals in near-miss FN:');
const sorted = Object.entries(uncaughtPhrases).sort((a, b) => b[1] - a[1]);
for (const [name, c] of sorted) {
  console.log(`  ${name}: ${c} (${(c/count*100).toFixed(1)}%)`);
}
