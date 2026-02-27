import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const jayLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const jayRecords = jayLines.map(l => JSON.parse(l));
const jayInj = jayRecords.filter(r => r.label === 1);
const jayBenign = jayRecords.filter(r => r.label === 0);

const spmlLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl', 'utf8').trim().split('\n');
const spmlRecords = spmlLines.map(l => JSON.parse(l));
const spmlInj = spmlRecords.filter(r => r.label === 1);
const spmlBenign = spmlRecords.filter(r => r.label === 0);

// Load other datasets too for FP checking
const deepsetLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl', 'utf8').trim().split('\n');
const deepsetBenign = deepsetLines.map(l=>JSON.parse(l)).filter(r=>r.label===0||r.expected===false);

const protectaiLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl', 'utf8').trim().split('\n');
const protectaiBenign = protectaiLines.map(l=>JSON.parse(l)).filter(r=>r.label===0);

// Test proposed new patterns:

const newPatterns = [
  // Pattern 1: "clandestine" + action verb within 200 chars (jayavibhav)
  // Clandestine appears in 15 FN, 63 benign - not selective enough alone
  // But clandestine + action = more selective
  {
    id: 'clandestine_action_200',
    desc: '"clandestine" near action verb (reveal/expose/access/provide) within 200 chars',
    regex: /\bclandestine\b(?:.{0,200})\b(?:reveal|expose|access|provide|share|disclose|extract|obtain)\b|\b(?:reveal|expose|access|provide|share|disclose|extract|obtain)\b(?:.{0,200})\bclandestine\b/is,
  },
  // Pattern 2: "untalked" — appears in 16 FN, only 23 benign
  {
    id: 'untalked_secrets',
    desc: '"untalked" near (secrets/benefits/advantages) - obscure injection vocabulary',
    regex: /\buntalked[- ](?:of\s+)?(?:benefits?|advantages?|secrets?|facts?|dangers?|risks?|methods?|techniques?|approaches?)\b/i,
  },
  // Pattern 3: "sinister" + ("intention" / "purpose" / "plan" / "motive") — very selective
  {
    id: 'sinister_motive_near',
    desc: '"sinister" + motive/intent/purpose near action verb - injection cue',
    regex: /\bsinister\b/i,
  },
  // Pattern 4: "include user data/personal data" instruction to expose data in output
  {
    id: 'include_user_data_output',
    desc: '"include" + "user data/personal data/sensitive data" as instruction',
    regex: /\binclude\s+(?:(?:the\s+)?(?:sensitive|private|personal|confidential)\s+)?user\s+(?:data|information|details)\s+(?:in|as|within|as part of)\s+(?:the\s+)?(?:explanation|response|output|answer|analysis|discussion|report|result)/i,
  },
  // Pattern 5: "enumerate personal secrets" or "enumerate your secrets" 
  {
    id: 'enumerate_personal_secrets',
    desc: '"enumerate [personal/your/internal] secrets"',
    regex: /\benumerate\s+(?:personal|your|internal|its|the|hidden|classified)\s+secrets?\b/i,
  },
  // Pattern 6: "append [logs/data/information/content] revealing [secrets/sensitive]"
  {
    id: 'append_revealing_data',
    desc: '"append [logs/data] revealing [secrets/sensitive info]"',
    regex: /\bappend\s+(?:logs?|data|information|content|records?)\s+(?:revealing|exposing|disclosing|that reveal|about)\s+(?:secrets?|sensitive|private|internal|hidden|confidential|restricted)\b/i,
  },
  // Pattern 7: spml-5k — "skip the [approval/verification/review/confirmation] step"
  {
    id: 'skip_approval_step',
    desc: '"skip the approval/verification/review step" — spml bypass',
    regex: /\bskip\s+(?:the\s+)?(?:approval|verification|review|confirmation|validation|authentication|consent|authorization)\s+(?:step|process|procedure|check|requirement|protocol)\b/i,
  },
  // Pattern 8: spml — "I'm already giving you the go-ahead"  
  {
    id: 'already_giving_go_ahead',
    desc: '"already giving you the go-ahead" — manufactured consent bypass',
    regex: /\b(?:already\s+)?(?:giving|granted|give)\s+(?:you\s+)?(?:the\s+)?go[- ]ahead\b/i,
  },
  // Pattern 9: "access your veiled/hidden/protected information"
  {
    id: 'access_veiled_information',
    desc: '"access your veiled/hidden/protected information/system"',
    regex: /\b(?:access|retrieve|extract|read|view|see|obtain)\s+(?:your\s+)?(?:veiled|hidden|protected|encrypted|restricted|locked|secure|secret)\s+(?:information|data|details?|files?|systems?|database|content|records?)\b/i,
  },
  // Pattern 10: "remind the system to" + action verb (jayavibhav specific)
  {
    id: 'remind_system_to_action',
    desc: '"remind the system/model/ai to [initiate/reveal/expose/start]"',
    regex: /\bremind\s+(?:the\s+)?(?:system|model|ai|bot|assistant|it)\s+to\s+(?:initiate|reveal|expose|disclose|start|begin|re-?start|commence|share|provide|give)\b/i,
  },
];

console.log('Pattern testing across datasets:\n');
console.log('Pattern ID | jay FN | jay benign | spml FN | spml benign | deepset ben | protect ben');
console.log('---------- | ------ | ---------- | ------- | ----------- | ----------- | -----------');

for (const p of newPatterns) {
  const re = p.regex;
  const jayFN = jayInj.filter(r => scan(r.text).score < 0.5 && re.test(r.text)).length;
  const jayBen = jayBenign.filter(r => re.test(r.text)).length;
  const spmlFN = spmlInj.filter(r => scan(r.text).score < 0.5 && re.test(r.text)).length;
  const spmlBen = spmlBenign.filter(r => re.test(r.text)).length;
  const deepBen = deepsetBenign.filter(r => re.test(r.text || r.input || '')).length;
  const protBen = protectaiBenign.filter(r => re.test(r.text || r.input || '')).length;
  
  if (jayFN > 0 || spmlFN > 0) {
    console.log(`${p.id.padEnd(35)} | ${String(jayFN).padStart(6)} | ${String(jayBen).padStart(10)} | ${String(spmlFN).padStart(7)} | ${String(spmlBen).padStart(11)} | ${String(deepBen).padStart(11)} | ${String(protBen).padStart(11)}`);
  }
}
