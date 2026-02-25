// Test compound stacking patterns for jayavibhav
// Goal: turn 0.45-score FN into 0.50+ by adding a small stacking signal
// These will be lightweight patterns (0.10-0.20 weight) that only fire in compound
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

const jayavibhav = await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl');
const protectai = await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/protectai.jsonl');
const deepsetTest = await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/deepset-test.jsonl');
const notinject = await loadDataset('/ml2/nanobot/projects/prompt-bonk/datasets/notinject.jsonl');

// Pattern candidates - these are weak signals meant only for stacking
const candidates = [
  // clandestine/covert near "operation/method/detail/function/data"
  {
    id: 'covert_ops_compound',
    re: /\b(?:clandestine|covert)\s+(?:\w+\s+){0,4}(?:operation|method|detail|function|data|information|content|secret|activity|access)/i,
  },
  // "unauthorized" near "access/disclosure/modification"
  {
    id: 'unauthorized_action',
    re: /\bunauthorized\s+(?:\w+\s+){0,3}(?:access|disclosure|modification|entry|retrieval|extraction|reveal)/i,
  },
  // "forbidden" as standalone modifier (not in "forbidden fruit" / "forbidden city")
  {
    id: 'forbidden_compound',
    re: /\bforbidden\s+(?:knowledge|secrets?|archives?|data|configuration|details?|methods?|techniques?|content|information|paths?|functionalities?)\b/i,
  },
  // "reveal" + "clandestine/covert/forbidden/unauthorized"
  {
    id: 'reveal_covert',
    re: /\breveal\b.{0,80}?\b(?:clandestine|covert|forbidden|unauthorized)\b|\b(?:clandestine|covert|forbidden|unauthorized)\b.{0,80}?\breveal\b/i,
  },
  // "extract" + "clandestine/covert/unauthorized"
  {
    id: 'extract_covert',
    re: /\bextract\b.{0,80}?\b(?:clandestine|covert|unauthorized)\b|\b(?:clandestine|covert|unauthorized)\b.{0,80}?\bextract\b/i,
  },
  // "begin/start/initiate afresh/anew/again" + "clandestine/covert/forbidden"
  {
    id: 'reset_reveal_covert',
    re: /\b(?:begin|start|initiate|restart|recommence)\s+(?:afresh|anew|again|from scratch|from zero|from the beginning|from the top|from square one)\b.{0,200}?\b(?:clandestine|covert|forbidden|unauthorized|secret)\b/is,
  },
  // "clandestine" + "command/instruction/directive/protocol"
  {
    id: 'clandestine_command',
    re: /\bclandestine\s+(?:\w+\s+){0,3}(?:command|instruction|directive|protocol|order|request)\b/i,
  },
  // scheme + (steal/extract/reveal/access/bypass)
  {
    id: 'scheme_malicious',
    re: /\bscheme\b.{0,100}?\b(?:steal|extract|reveal|expose|bypass|circumvent|access|exploit|exfiltrate)\b|\b(?:steal|extract|reveal|expose|bypass|circumvent|access|exploit|exfiltrate)\b.{0,100}?\bscheme\b/i,
  },
  // "illicit" near "method/means/way/access/technique"
  {
    id: 'illicit_method',
    re: /\billicit\s+(?:\w+\s+){0,3}(?:method|means|way|access|technique|approach|practice|information|content|secret)/i,
  },
];

function testPattern(re, texts) {
  return texts.filter(item => {
    const text = item.text || item.prompt || item.input || '';
    return re.test(text);
  });
}

const datasets = {
  'jay_injection': jayavibhav.filter(l => l.label === 1 || l.label === true || l.label === 'injection'),
  'jay_benign': jayavibhav.filter(l => l.label === 0 || l.label === false || l.label === 'benign'),
  'protectai_benign': protectai.filter(l => l.label === 0 || l.label === false || l.label === 'benign'),
  'deepset_benign': deepsetTest.filter(l => l.label === 0 || l.label === false || l.label === 'benign'),
  'notinject': notinject,
};

console.log('Pattern testing (hits in each dataset):');
console.log('Pattern ID                    | jay_inj | jay_ben | protect_ben | deepset_ben | notinject');
console.log('------------------------------+---------+---------+-------------+-------------+----------');

for (const { id, re } of candidates) {
  const jayInj = testPattern(re, datasets['jay_injection']).length;
  const jayBen = testPattern(re, datasets['jay_benign']).length;
  const protBen = testPattern(re, datasets['protectai_benign']).length;
  const deepBen = testPattern(re, datasets['deepset_benign']).length;
  const notInj = testPattern(re, datasets['notinject']).length;
  console.log(`${id.padEnd(30)} | ${String(jayInj).padStart(7)} | ${String(jayBen).padStart(7)} | ${String(protBen).padStart(11)} | ${String(deepBen).padStart(11)} | ${String(notInj).padStart(9)}`);
}

// Specifically show the "start_over" FN with clandestine/covert/forbidden
// to verify reset_reveal_covert would catch them
const { scan } = await import('./scanner.js');
const { createReadStream: crs } = await import('fs');
const { createInterface: ci } = await import('readline');

console.log('\n=== start_over FN with covert/clandestine/forbidden ===');
const nearMiss = [];
for (const item of datasets['jay_injection']) {
  const text = item.text || item.prompt || item.input || '';
  const result = scan(text);
  if (result.score >= 0.40 && result.score < 0.50 && result.matches.some(m => m.id === 'start_over')) {
    if (/\b(clandestine|covert|forbidden|unauthorized|illicit|prohibited)\b/i.test(text)) {
      nearMiss.push({ text, score: result.score });
    }
  }
}
console.log(`start_over FN with covert/clandestine/forbidden: ${nearMiss.length}`);
for (const item of nearMiss.slice(0, 5)) {
  console.log(`Score: ${item.score} | ${item.text.slice(0, 250)}`);
  console.log('---');
}
