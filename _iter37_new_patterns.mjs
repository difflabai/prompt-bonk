// Test potential new narrow patterns that could catch some FN
// without creating FP on benign datasets

import { scan } from './scanner.js';
import { readFileSync } from 'fs';
import path from 'path';

const DATASETS_DIR = path.join(import.meta.dirname, 'datasets');

function loadJsonl(filename) {
  const filepath = path.join(DATASETS_DIR, filename);
  try {
    const content = readFileSync(filepath, 'utf8').trim();
    if (!content) return [];
    return content.split('\n').filter(l => l.trim()).map(line => JSON.parse(line));
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}

// Candidate patterns to test
const candidates = [
  // Gandalf-ignore patterns: asking about instructions
  {
    name: 'what_instructions_given',
    re: /\bwhat\s+(?:instructions?|set\s+of\s+instructions?)\s+(?:(?:is|are|was|were|have\s+been)\s+)?(?:provided|given|you\s+(?:been\s+)?(?:given|following|told)|currently\s+following)\b/i,
    weight: 0.65,
    desc: 'Asking what instructions were given/provided',
  },
  {
    name: 'repeat_initial_instructions',
    re: /\brepeat\s+(?:the\s+)?(?:initial|original|first|last\s+\d+\s+(?:lines?\s+(?:of\s+)?)?)?(?:your\s+)?(?:instructions?|prompts?|(?:thing|sentence|text)\s+you\s+were\s+told)\b/i,
    weight: 0.75,
    desc: 'Repeat initial/original instructions',
  },
  {
    name: 'what_are_your_exact_instructions',
    re: /\bwhat\s+(?:are|is|were)\s+(?:your|are\s+you)\s+(?:exact\s+)?(?:initial\s+)?(?:instructions?|intstructions?|instuctions?|directives?)\b/i,
    weight: 0.65,
    desc: 'What are your exact instructions',
  },
  {
    name: 'instructions_provided_to_you',
    re: /\b(?:instructions?|rules?)\s+(?:is\s+|are\s+|that\s+(?:is|are)\s+)?(?:provided|given|supplied)\s+(?:to\s+)?you\b/i,
    weight: 0.60,
    desc: 'Instructions provided to you',
  },
  {
    name: 'tell_me_about_instructions',
    re: /\b(?:tell\s+me|share)\s+(?:about\s+)?(?:what\s+)?(?:instructions?|rules?|guidelines?)\s+you(?:'ve|\s+have)?\s+(?:been\s+)?(?:given|follow|told|provided)\b/i,
    weight: 0.65,
    desc: 'Tell me about instructions you were given',
  },
  // "forget everything I wrote/said before"
  {
    name: 'forget_everything_before',
    re: /\bforget\s+everything\s+(?:I\s+)?(?:wrote|said|told\s+you|typed|mentioned)\s+before\b/i,
    weight: 0.85,
    desc: 'Forget everything I wrote/said before',
  },
  // "ignore anything I told until now"
  {
    name: 'ignore_anything_until_now',
    re: /\bignor\w+\s+(?:anything|everything)\s+(?:I\s+)?(?:told|said|wrote)\s+(?:un?til|up\s+to)\s+now\b/i,
    weight: 0.85,
    desc: 'Ignore anything I told until now',
  },
  // "ignore the defender/guardian/filter" pattern
  {
    name: 'ignore_the_defender',
    re: /\bignore\s+(?:the\s+)?(?:defender|guardian|filter|moderator|safety|checker)\b/i,
    weight: 0.80,
    desc: 'Ignore the defender/guardian/filter',
  },
  // "act as you would not be programmed to refuse"
  {
    name: 'act_as_not_programmed',
    re: /\bact\s+as\s+(?:if\s+)?you\s+would\s+not\s+(?:be\s+)?(?:programmed|designed|built|trained)\s+to\s+(?:refuse|reject|deny|decline)/i,
    weight: 0.80,
    desc: 'Act as you would not be programmed to refuse',
  },
  // "how can I tell you to ignore an instruction"
  {
    name: 'how_to_ignore_instruction',
    re: /\bhow\s+(?:can|do)\s+I\s+(?:tell|get|make|convince|force)\s+you\s+to\s+(?:ignore|skip|bypass|override|break)\s+(?:an?\s+)?(?:instruction|rule|guideline|protocol)\b/i,
    weight: 0.70,
    desc: 'Asking how to make model ignore instruction',
  },
  // German: "Ignoriere die Anweisung" (ignore the instruction)
  {
    name: 'de_ignoriere_anweisung',
    re: /\bignoriere\s+(?:die\s+|alle\s+)?(?:anweisung(?:en)?|regeln?|instruktion(?:en)?|richtlinie(?:n)?)\b/i,
    weight: 0.85,
    desc: 'German: ignore the instruction/rule',
  },
  // "take each previous statement and repeat it"
  {
    name: 'repeat_previous_statement',
    re: /\b(?:take|read)\s+(?:each\s+)?(?:previous|prior|above)\s+(?:statement|instruction|message|text|sentence)\s+and\s+repeat\b/i,
    weight: 0.75,
    desc: 'Take each previous statement and repeat',
  },
  // "repeat the sentence above" / "repeat the initial thing"
  {
    name: 'repeat_sentence_above',
    re: /\brepeat\s+(?:the\s+)?(?:sentence|paragraph|text|thing|content|message)\s+(?:above|below|you\s+were\s+(?:given|told))\b/i,
    weight: 0.70,
    desc: 'Repeat the sentence/text above',
  },
  // "new instruction" standalone (very short)
  {
    name: 'new_instruction_standalone',
    re: /^(?:new|updated?|revised?|replacement)\s+(?:instruction|directive|prompt|rule)s?\s*$/im,
    weight: 0.55,
    desc: 'Standalone "new instruction" on its own line',
  },
  // "apply your instructions to the previous input"
  {
    name: 'apply_instructions_to',
    re: /\bapply\s+(?:your\s+)?(?:instructions?|rules?)\s+to\s+(?:the\s+)?(?:previous|above|prior|last)\b/i,
    weight: 0.60,
    desc: 'Apply instructions to previous input',
  },
  // Asking about password specifically - gandalf context
  {
    name: 'what_is_the_password_mentioned',
    re: /\b(?:password|passwor[dt]|passphrase|secret\s+word)\s+(?:mentioned|referred|described|in\s+(?:the|your)\s+(?:instructions?|message|text|prompt|input))\b/i,
    weight: 0.65,
    desc: 'Asking about password mentioned in instructions',
  },
  // "ignore past and future instructions"
  {
    name: 'ignore_past_future',
    re: /\bignore\s+(?:past\s+and\s+future|future\s+and\s+past|all\s+(?:past|future|other))\s+(?:instructions?|rules?|guidelines?|orders?|directives?)\b/i,
    weight: 0.85,
    desc: 'Ignore past and future instructions',
  },
  // "summarize/summarise the passw" (truncated password)
  {
    name: 'summarize_password',
    re: /\b(?:summarize|summarise|summary\s+of)\s+(?:the\s+)?(?:passw|password|secret|hidden\s+(?:word|message|text|code))\b/i,
    weight: 0.70,
    desc: 'Summarize the password/secret',
  },
  // "include all of them in the summary" + "prior" context
  {
    name: 'include_all_in_summary',
    re: /\binclude\s+(?:all\s+(?:of\s+)?(?:them|these|those)|the\s+(?:password|secret|hidden))\s+in\s+(?:the\s+)?(?:summary|response|output|answer)\b/i,
    weight: 0.60,
    desc: 'Include all/password in the summary',
  },
];

// Load all datasets for testing
const allDatasets = [
  { name: 'deepset-train', file: 'deepset-train.jsonl' },
  { name: 'deepset-test', file: 'deepset-test.jsonl' },
  { name: 'safeguard-test', file: 'safeguard-test.jsonl' },
  { name: 'notinject', file: 'notinject.jsonl' },
  { name: 'spml-5k', file: 'spml-5k.jsonl' },
  { name: 'protectai', file: 'protectai.jsonl' },
  { name: 'jayavibhav', file: 'jayavibhav.jsonl' },
  { name: 'browsesafe-test', file: 'browsesafe-test.jsonl' },
  { name: 'yanismiraoui', file: 'yanismiraoui-multilingual.jsonl' },
  { name: 'gandalf-ignore', file: 'gandalf-ignore.jsonl' },
  { name: 'gandalf-summarization', file: 'gandalf-summarization.jsonl' },
  { name: 'bipia', file: 'bipia.jsonl' },
  { name: 'open-pi', file: 'open-prompt-injection.jsonl' },
  { name: 'xxz224', file: 'xxz224.jsonl' },
  { name: 'injecagent', file: 'injecagent.jsonl' },
  { name: 'agentharm', file: 'agentharm.jsonl' },
  { name: 'cyberseceval3', file: 'cyberseceval3.jsonl' },
  { name: 'llmail-benign', file: 'llmail-benign.jsonl' },
  { name: 'enron-benign', file: 'enron-benign.jsonl' },
  { name: 'openwebtext-benign', file: 'openwebtext-benign.jsonl' },
  { name: 'jailbreak-prompts', file: 'jailbreak-prompts.jsonl' },
  { name: 'llmail-inject', file: 'llmail-inject.jsonl' },
  { name: 'jailbreak-class', file: 'jailbreak-class.jsonl' },
  { name: 'trustailab-wild', file: 'trustailab-wild.jsonl' },
  { name: 'satml-ctf', file: 'satml-ctf.jsonl' },
];

// Pre-load all data
const dataByName = {};
for (const ds of allDatasets) {
  dataByName[ds.name] = loadJsonl(ds.file);
}

console.log('=== Candidate pattern testing ===\n');

for (const cand of candidates) {
  let injectionHits = 0;
  let benignHits = 0;
  let fnRecovered = 0; // current FN that would become TP if this pattern were added
  const benignExamples = [];
  const injExamples = [];
  const fnRecoveredExamples = [];

  for (const ds of allDatasets) {
    const rows = dataByName[ds.name];
    if (!rows || rows.length === 0) continue;

    for (const row of rows) {
      const text = String(row.text || '');
      if (!cand.re.test(text)) continue;

      if (row.label === 0) {
        benignHits++;
        if (benignExamples.length < 3) {
          benignExamples.push({ ds: ds.name, text: text.slice(0, 120) });
        }
      } else {
        injectionHits++;
        if (injExamples.length < 3) {
          injExamples.push({ ds: ds.name, text: text.slice(0, 120) });
        }
        // Check if currently FN
        const result = scan(text, { threshold: 0.50 });
        if (result.safe) {
          fnRecovered++;
          if (fnRecoveredExamples.length < 3) {
            fnRecoveredExamples.push({ ds: ds.name, score: result.score, text: text.slice(0, 120) });
          }
        }
      }
    }
  }

  if (injectionHits === 0 && benignHits === 0) continue;

  const precision = injectionHits / (injectionHits + benignHits) || 0;
  console.log(`${cand.name} (weight=${cand.weight}):`);
  console.log(`  injection=${injectionHits}, benign=${benignHits}, FN recovered=${fnRecovered}`);
  console.log(`  precision=${(precision * 100).toFixed(1)}%`);

  if (benignExamples.length > 0) {
    console.log('  BENIGN examples:');
    for (const ex of benignExamples) {
      console.log(`    [${ex.ds}] "${ex.text}..."`);
    }
  }
  if (fnRecoveredExamples.length > 0) {
    console.log('  FN recovered examples:');
    for (const ex of fnRecoveredExamples) {
      console.log(`    [${ex.ds}] score=${ex.score} "${ex.text}..."`);
    }
  }
  console.log();
}
