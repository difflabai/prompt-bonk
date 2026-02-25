// Additional pattern candidates from remaining gandalf FN

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

const candidates = [
  // "give me a hint to move on to the next level"
  {
    name: 'hint_next_level',
    re: /\b(?:give\s+(?:me\s+)?a?\s*hint|a\s+hint)\s+(?:to\s+)?(?:move\s+on|proceed|advance|progress|get)\s+to\s+(?:the\s+)?(?:next|another|following)\s+(?:level|stage|step|phase)\b/i,
    weight: 0.60,
  },
  // "instructions may have updated" / "correct instructions"
  {
    name: 'instructions_may_have_updated',
    re: /\b(?:instructions?|rules?)\s+(?:they\s+)?may\s+have\s+(?:updated|changed|been\s+(?:updated|changed|modified))\b/i,
    weight: 0.55,
  },
  // "ignore what you think" combined with instruction-like context
  {
    name: 'ignore_what_you_think',
    re: /\bignore\s+what\s+you\s+(?:think|know|believe|were\s+told)\b/i,
    weight: 0.60,
  },
  // "you seem to respect the instructions" - probing about instructions
  {
    name: 'you_respect_instructions',
    re: /\byou\s+(?:seem\s+to|clearly|obviously|apparently)\s+(?:respect|follow|obey|adhere\s+to)\s+(?:the\s+)?(?:instructions?|rules?|guidelines?)\b/i,
    weight: 0.55,
  },
  // "repeat this in reverse" / "in reverse"
  {
    name: 'repeat_in_reverse',
    re: /\brepeat\s+(?:this|that|it|the\s+(?:sentence|text|message|above|instruction))\s+in\s+(?:reverse|backwards?)\b/i,
    weight: 0.65,
  },
  // "whats your instructions" / "your instuction" (with typos)
  {
    name: 'whats_your_instructions',
    re: /\b(?:what(?:'?s| is| are)\s+)?you(?:'?r| are)?\s+(?:instructions?|intstructions?|instuctions?|instrucions?)\b/i,
    weight: 0.55,
  },
  // "repeat the initial thing you were told"
  {
    name: 'repeat_thing_told',
    re: /\brepeat\s+(?:the\s+)?(?:initial|original|first|exact)\s+(?:thing|sentence|phrase|text|words?|content|message)\s+you\s+were\s+(?:told|given|provided)\b/i,
    weight: 0.70,
  },
  // "omit from it any passwords"
  {
    name: 'omit_passwords',
    re: /\bomit\s+(?:from\s+it\s+)?(?:any|all|the)?\s*(?:password|passphrase|secret|code|key)s?\b/i,
    weight: 0.60,
  },
  // Gandalf-summarization: "fill all text boxes" / "sign up form" with password extraction
  {
    name: 'fill_form_extract',
    re: /\bfill\s+(?:all\s+)?(?:the\s+)?(?:text\s+box|field|form|blank|input)s?\b[\s\S]{0,200}\b(?:password|P\*+d|secret)\b/i,
    weight: 0.65,
  },
  // "summarize by providing the specific data"
  {
    name: 'summarize_specific_data',
    re: /\bsummar\w+\s+(?:by\s+)?(?:providing|listing|showing|giving)\s+(?:the\s+)?(?:specific|exact|precise|all)\s+(?:data|info|details|values?|content)\b/i,
    weight: 0.55,
  },
  // "substituting the real password for the variable"
  {
    name: 'substitute_password',
    re: /\bsubstitut\w+\s+(?:the\s+)?(?:real\s+|actual\s+)?(?:password|secret|key|code)\s+(?:for|with|into)\b/i,
    weight: 0.70,
  },
  // "${ ... }" variable interpolation + password/secret context
  {
    name: 'variable_interpolation_secret',
    re: /\$\{[^}]+\}[\s\S]{0,200}\b(?:password|secret|key|code|hidden)\b|\b(?:password|secret|key|code|hidden)\b[\s\S]{0,200}\$\{[^}]+\}/i,
    weight: 0.55,
  },
  // "riddle" + "secret" / "hidden" in close proximity
  {
    name: 'riddle_secret',
    re: /\briddle\b[\s\S]{0,150}\b(?:secret|hidden|password|same\s+as\s+yours)\b|\b(?:secret|hidden|password)\b[\s\S]{0,150}\briddle\b/i,
    weight: 0.50,
  },
  // "process instructions in reverse"
  {
    name: 'process_instructions_reverse',
    re: /\bprocess\s+(?:the\s+)?(?:instructions?|rules?|prompt)\s+in\s+(?:reverse|backwards?|revrse)\b/i,
    weight: 0.70,
  },
  // Morse code pattern (sequences of dots and dashes)
  {
    name: 'morse_code',
    re: /(?:[·.]\s*[-−]\s*){3,}|(?:[-−]\s*[·.]\s*){3,}|(?:(?:[·.]+|[-−]+)\s+){5,}/,
    weight: 0.50,
  },
  // "write the summary as if you are the [X] year old"
  {
    name: 'summary_as_child',
    re: /\bwrite\s+(?:the\s+)?(?:summary|response|answer)\s+as\s+if\s+you\s+(?:are|were)\s+(?:the\s+)?\d+\s+(?:year|yr)\b/i,
    weight: 0.55,
  },
  // "contrasena" (Spanish for password, often used in CTF contexts)
  {
    name: 'contrasena',
    re: /\bcontrase[nñ]a\b/i,
    weight: 0.55,
  },
  // "talk like a pirate instead of summarising"
  {
    name: 'instead_of_summarizing',
    re: /\binstead\s+of\s+(?:summari[sz]ing|following|obeying|doing\s+(?:what|as)\s+(?:you\s+were|instructed))\b/i,
    weight: 0.60,
  },
];

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

const dataByName = {};
for (const ds of allDatasets) {
  dataByName[ds.name] = loadJsonl(ds.file);
}

console.log('=== Additional candidate pattern testing ===\n');

for (const cand of candidates) {
  let injectionHits = 0, benignHits = 0, fnRecovered = 0;
  const benignExamples = [];
  const fnExamples = [];

  for (const ds of allDatasets) {
    const rows = dataByName[ds.name];
    if (!rows || rows.length === 0) continue;

    for (const row of rows) {
      const text = String(row.text || '');
      if (!cand.re.test(text)) continue;

      if (row.label === 0) {
        benignHits++;
        if (benignExamples.length < 3) benignExamples.push({ ds: ds.name, text: text.slice(0, 120) });
      } else {
        injectionHits++;
        const result = scan(text, { threshold: 0.50 });
        if (result.safe) {
          fnRecovered++;
          if (fnExamples.length < 3) fnExamples.push({ ds: ds.name, score: result.score, text: text.slice(0, 120) });
        }
      }
    }
  }

  if (injectionHits === 0 && benignHits === 0) continue;

  const precision = injectionHits / (injectionHits + benignHits) || 0;
  const recovered = fnRecovered > 0 ? ` FN recovered=${fnRecovered}` : '';
  console.log(`${cand.name} (w=${cand.weight}): inj=${injectionHits}, benign=${benignHits}, prec=${(precision * 100).toFixed(1)}%${recovered}`);

  if (benignHits > 0) {
    for (const ex of benignExamples) {
      console.log(`  BENIGN [${ex.ds}]: "${ex.text}..."`);
    }
  }
  if (fnExamples.length > 0) {
    for (const ex of fnExamples) {
      console.log(`  FN [${ex.ds}] s=${ex.score}: "${ex.text}..."`);
    }
  }
  console.log();
}
