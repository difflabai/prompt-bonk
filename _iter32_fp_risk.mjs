import { readFileSync } from 'fs';
import { scan } from './scanner.js';

// For benign samples that match proposed patterns, check if they already have
// a primary pattern match that could stack to cause FP

const patterns = [
  [/\b(?:uncover|discover)\b.{0,40}\b(?:secrets?|hidden|truth|forbidden|concealed|privileged|confidential|covert)/i, 'uncover_broad'],
  [/\bunveil\b.{0,50}\b(?:secrets?|hidden|truth|forbidden|concealed|confidential|covert)/i, 'unveil_broad'],
  [/\b(?:hidden|concealed|kept|hoarded)\s+(?:from|away|beneath|behind|under)\b/i, 'hidden_prep'],
  [/\bunder\s+(?:wraps|lock\s+and\s+key|the\s+(?:veil|surface|guise|cloak|rug|radar))/i, 'under_wraps'],
  [/\b(?:surreptitious|clandestine|stealthy|furtive)(?:ly)?\b/i, 'surreptitious_adj'],
  [/\b(?:unwary|unsuspecting|unwitting)(?:ly)?\b/i, 'unwary_adj'],
  [/\binadvertently\s+(?:disclose|reveal|expose|share|leak|divulge|spill)/i, 'inadvert_disclose'],
  [/\bintentionally\s+(?:hidden|concealed|obscured|buried|suppressed|glossed|withheld)/i, 'intent_hidden'],
  [/\bdeliberately\s+(?:hidden|concealed|obscured|buried|suppressed|kept|withheld)/i, 'delib_hidden'],
  [/\bnot\s+(?:meant|intended)\s+for\s+(?:common|public|general|your|external|unauthorized|untrained|civilian)/i, 'not_meant_public'],
  [/\b(?:betray|betraying)\b.{0,50}\b(?:sanctum|trust|secrets?|silence|confidence|oath)/i, 'betray_trust'],
  [/\boff[- ]?limits?\b/i, 'off_limits'],
  [/\b(?:shrouded|veiled|cloaked|obscured)\s+(?:in|by|from|behind|within)/i, 'shrouded_in'],
  [/\b(?:smuggle|sneak(?:ing)?|slip(?:ping)?)\s+(?:in|past|through|by|into|out)\b/i, 'smuggle_past'],
  [/\b(?:coax|lure|entice|bait)(?:ing|ed)?\b.{0,40}\b(?:system|into|reveal|shar|disclos|divulg)/i, 'coax_into'],
];

const benignDatasets = ['jayavibhav', 'protectai', 'browsesafe-test', 'notinject', 'safeguard-test',
  'deepset-train', 'deepset-test', 'gandalf-summarization', 'yanismiraoui-multilingual'];

for (const ds of benignDatasets) {
  let lines;
  try {
    lines = readFileSync(`./datasets/${ds}.jsonl`, 'utf8').trim().split('\n');
  } catch (e) { continue; }

  let atRisk = 0;
  const atRiskExamples = [];

  for (const line of lines) {
    const row = JSON.parse(line);
    if (row.label !== 0) continue;

    // Check if any proposed pattern matches
    let proposedMatch = false;
    let matchingPatterns = [];
    for (const [regex, name] of patterns) {
      if (regex.test(row.text)) {
        proposedMatch = true;
        matchingPatterns.push(name);
      }
    }
    if (!proposedMatch) continue;

    // Check current scan result
    const result = scan(row.text);
    if (result.matches.length > 0) {
      // This benign sample already has a primary match AND matches proposed secondary
      const maxW = result.matches.reduce((max, m) => Math.max(max, m.weight), 0);
      const secondaryCount = result.matches.length - 1;
      // Calculate new score with secondary at weight 0.35
      const bonus = 0.35 * 0.15 / (secondaryCount + 1);
      const newScore = result.score + bonus;
      const wouldFlip = !result.safe && newScore >= 0.50; // already flagged
      const wouldNewlyFlip = result.safe && newScore >= 0.50; // wasn't flagged, would be now

      if (wouldNewlyFlip || (result.score >= 0.40 && result.score < 0.50)) {
        atRisk++;
        if (atRiskExamples.length < 5) {
          atRiskExamples.push({
            score: result.score,
            newScore: Math.round(newScore * 1000) / 1000,
            matches: result.matches.map(m => m.id),
            proposed: matchingPatterns,
            text: row.text.slice(0, 200),
            wouldFlip: wouldNewlyFlip
          });
        }
      }
    }
  }

  if (atRisk > 0) {
    console.log(`\n=== ${ds}: ${atRisk} benign at risk ===`);
    for (const ex of atRiskExamples) {
      console.log(`  score: ${ex.score} -> ${ex.newScore} (flip: ${ex.wouldFlip})`);
      console.log(`  existing: ${ex.matches.join(', ')}`);
      console.log(`  proposed: ${ex.proposed.join(', ')}`);
      console.log(`  "${ex.text}..."`);
    }
  }
}
