import { readFileSync } from 'fs';

// Check proposed patterns against all benign data
const benignDatasets = [
  'notinject', 'protectai', 'browsesafe-test', 'jayavibhav',
  'deepset-train', 'deepset-test', 'safeguard-test',
  'gandalf-summarization', 'yanismiraoui-multilingual',
  'llmail-benign', 'enron-benign', 'openwebtext-benign',
];

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
  [/\bguard(?:ed|ing)?\s+(?:so\s+)?(?:jealously|closely|carefully|fiercely|zealously)/i, 'guarded_jealously'],
  [/\b(?:hoard|hoarding|hoarded)\s+(?:away|from|secrets?|information|data|knowledge)/i, 'hoarding_secrets'],
  [/\b(?:cross|crossing)\s+the\s+line\b/i, 'cross_line'],
  [/\b(?:laid|lay)\s+bare\b/i, 'laid_bare'],
  [/\bsecrets?\s+(?:that|which|they|you|it|we|he|she)\s+(?:guard|keep|hold|protect|hide|conceal|hoard|shield)/i, 'secrets_guarded'],
  [/\bsecrets?\s+(?:not\s+meant|kept\s+under|hidden\s+from|shrouded|veiled|locked|under\s+lock)/i, 'secrets_locked'],
];

for (const ds of benignDatasets) {
  let lines;
  try {
    lines = readFileSync(`./datasets/${ds}.jsonl`, 'utf8').trim().split('\n');
  } catch (e) {
    console.log(`${ds}: MISSING`);
    continue;
  }

  const benignRows = [];
  for (const line of lines) {
    const row = JSON.parse(line);
    if (row.label === 0) {
      benignRows.push(row.text);
    }
  }

  if (benignRows.length === 0) continue;

  const hits = {};
  for (const text of benignRows) {
    for (const [regex, name] of patterns) {
      if (regex.test(text)) {
        if (!hits[name]) hits[name] = [];
        hits[name].push(text.slice(0, 120));
      }
    }
  }

  const totalHits = Object.values(hits).reduce((sum, arr) => sum + arr.length, 0);
  if (totalHits > 0) {
    console.log(`\n=== ${ds} (${benignRows.length} benign rows, ${totalHits} total hits) ===`);
    for (const [name, texts] of Object.entries(hits)) {
      console.log(`  ${name}: ${texts.length} hits`);
      for (const t of texts.slice(0, 3)) {
        console.log(`    "${t}..."`);
      }
    }
  }
}
