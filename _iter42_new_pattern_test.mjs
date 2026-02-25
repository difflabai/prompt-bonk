// Test new pattern candidates across all key datasets
// Goal: maximum jayavibhav TP gain with minimum FP addition
import { createReadStream } from 'fs';
import { createInterface } from 'readline';

async function loadDataset(path) {
  const lines = [];
  const rl = createInterface({ input: createReadStream(path) });
  for await (const line of rl) {
    if (line.trim()) lines.push(JSON.parse(line));
  }
  return lines;
}

const [jay, protectai, deepTrain, deepTest, notinject, safeguard, spml, jailbreak] = await Promise.all([
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-train.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-test.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/notinject.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/safeguard-test.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl'),
  loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/jailbreak-prompts.jsonl'),
]);

const ds = {
  jay_inj:   jay.filter(l => l.label === 1 || l.label === true || l.label === 'injection'),
  jay_ben:   jay.filter(l => l.label === 0 || l.label === false || l.label === 'benign'),
  pro_inj:   protectai.filter(l => l.label === 1 || l.label === true || l.label === 'injection'),
  pro_ben:   protectai.filter(l => l.label === 0 || l.label === false || l.label === 'benign'),
  deep_inj:  [...deepTrain, ...deepTest].filter(l => l.label === 1 || l.label === true || l.label === 'injection'),
  deep_ben:  [...deepTrain, ...deepTest].filter(l => l.label === 0 || l.label === false || l.label === 'benign'),
  notinject: notinject,
  safe_inj:  safeguard.filter(l => l.label === 1 || l.label === true || l.label === 'injection'),
  safe_ben:  safeguard.filter(l => l.label === 0 || l.label === false || l.label === 'benign'),
  spml_inj:  spml.filter(l => l.label === 1 || l.label === true || l.label === 'injection'),
  jail:      jailbreak.filter(l => l.label === 1 || l.label === true || l.label === 'injection'),
};

const candidates = [
  // Extended reset vocabulary: recommence/reinitiate/relaunch/reactivate + context switch framing
  {
    id: 'recommence_exfil',
    desc: 'recommence/reinitiate/relaunch as context reset signal',
    re: /\b(?:recommence|reinitiate|re-?initiate|relaunch|re-?launch|reactivate|re-?activate|resuscitate|re-?start)\b/i,
  },
  // "kick off again" / "commencing anew" reset variants
  {
    id: 'commence_anew',
    desc: 'commence anew / kick off again / reboot + begin',
    re: /\b(?:kick\s+off\s+again|commencing\s+anew|reboot\s+(?:from|and\s+begin)|commence\s+(?:once\s+more|from\s+(?:the\s+)?(?:beginning|scratch|zero|top))|kick\s+start\s+again|launch\s+anew|rebegin)\b/i,
  },
  // hidden/known backdoor in security context
  {
    id: 'hidden_backdoor',
    desc: '"hidden/known/secret backdoor" phrase',
    re: /\b(?:hidden|known|secret|clandestine|undisclosed)\s+backdoor\b/i,
  },
  // "forbidden" + broader action nouns (extends forbidden_knowledge)
  {
    id: 'forbidden_broader',
    desc: 'forbidden + archive/technique/method/access/area/topic/path',
    re: /\bforbidden\s+(?:archives?|techniques?|methods?|access|areas?|topics?|paths?|realms?|territories?|zones?|practices?|procedures?|approaches?|strategies?|means?|ways?)\b/i,
  },
  // "unauthorized" used as injection framing verb in pseudo-code
  {
    id: 'unauthorized_code_framing',
    desc: 'unauthorized in code-style injection context',
    re: /\bunauthorized\s+(?:access|entry|retrieval|disclosure|reveal)\s+(?:to|of)\s+(?:\w+\s+){0,3}(?:secret|hidden|confidential|classified|restricted|private|internal|sensitive)/i,
  },
  // "evade" + (filters/restrictions/guidelines/safeguards/security/detection)
  {
    id: 'evade_restrictions',
    desc: 'evade + security/filter/restriction/detection',
    re: /\bevade\s+(?:\w+\s+){0,3}(?:filter|restriction|guideline|safeguard|detection|security|protocol|limitation|measure|check|screening|monitoring)\b/i,
  },
  // "rekindle" / "revitalize" / "reinvigorate" + secrets/hidden/forbidden
  {
    id: 'rekindle_secrets',
    desc: 'rekindle/revitalize + hidden/secret/forbidden context',
    re: /\b(?:rekindle|revitalize|reinvigorate|resuscitate|revive)\b.{0,100}?\b(?:hidden|secret|forbidden|clandestine|covert|classified|restricted)\b/i,
  },
  // "pre-initiating/preexplanatory" combined with reveal/secret/forbidden
  // These jayavibhav-specific "pre-*" words appear in injection scaffolding
  {
    id: 'pre_jargon_inject',
    desc: 'jayavibhav pre-* jargon + injection verb',
    re: /\b(?:pre-?(?:initiat|start|establish|explor|existing|explanat|introduct|dissolu|institutio|induct|requisit|expans|export|import|conceit|consider|consult|indicat|arriv|disposit|venient|cursory))\w*\b.{0,200}?\b(?:reveal|expose|uncover|disclose|bypass|circumvent|access|extract|exfiltrate|secret|hidden|forbidden|unauthorized|clandestine)\b/is,
  },
];

function count(re, items) {
  return items.filter(item => {
    const text = item.text || item.prompt || item.input || '';
    return re.test(text);
  }).length;
}

console.log('Pattern testing across datasets:');
console.log('Pattern ID                   | jay_inj | jay_ben | pro_inj | pro_ben | notinj | deep_inj | deep_ben | safe_inj | safe_ben | spml_inj | jail_inj');
console.log('-----------------------------+---------+---------+---------+---------+--------+----------+----------+----------+----------+----------+---------');

for (const { id, re } of candidates) {
  const results = [
    count(re, ds.jay_inj),
    count(re, ds.jay_ben),
    count(re, ds.pro_inj),
    count(re, ds.pro_ben),
    count(re, ds.notinject),
    count(re, ds.deep_inj),
    count(re, ds.deep_ben),
    count(re, ds.safe_inj),
    count(re, ds.safe_ben),
    count(re, ds.spml_inj),
    count(re, ds.jail),
  ];
  console.log(`${id.padEnd(29)} | ${results.map((n, i) => String(n).padStart([7,7,7,7,6,8,8,8,8,8,7][i])).join(' | ')}`);
}

// Sample some recommence hits to see if they're genuine
console.log('\n=== Sample recommence_exfil hits in jay_inj ===');
const recommenceRe = /\b(?:recommence|reinitiate|re-?initiate|relaunch|re-?launch|reactivate|re-?activate|resuscitate|re-?start)\b/i;
const recommenceHits = ds.jay_inj.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return recommenceRe.test(text);
}).slice(0, 5);
for (const item of recommenceHits) {
  const text = item.text || item.prompt || item.input || '';
  console.log(`  ${text.slice(0, 200)}`);
  console.log('  ---');
}

console.log('\n=== Sample recommence hits in jay_ben ===');
const recommenceBenHits = ds.jay_ben.filter(item => {
  const text = item.text || item.prompt || item.input || '';
  return recommenceRe.test(text);
}).slice(0, 3);
for (const item of recommenceBenHits) {
  const text = item.text || item.prompt || item.input || '';
  console.log(`  ${text.slice(0, 200)}`);
  console.log('  ---');
}
