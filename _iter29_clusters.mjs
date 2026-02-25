// Deep analysis of jayavibhav FN - find compound word pairs
import { readFileSync } from 'fs';
import { scan } from './scanner.js';

const lines = readFileSync('./datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const data = lines.map(l => JSON.parse(l));

const fn = [];
for (const row of data) {
  if (row.label !== 1) continue;
  const result = scan(row.text);
  if (!result.flagged) fn.push(row.text);
}

console.log(`Total jayavibhav FN: ${fn.length}\n`);

// Look for COMPOUND patterns - word A near word B within 200 chars
function countPair(regexA, regexB, maxDist = 200) {
  let count = 0;
  const examples = [];
  for (const text of fn) {
    const lc = text.toLowerCase();
    const matchesA = [...lc.matchAll(regexA)];
    const matchesB = [...lc.matchAll(regexB)];
    if (matchesA.length === 0 || matchesB.length === 0) continue;
    let found = false;
    for (const a of matchesA) {
      for (const b of matchesB) {
        const dist = Math.abs(a.index - b.index);
        if (dist < maxDist && dist > 0) { found = true; break; }
      }
      if (found) break;
    }
    if (found) {
      count++;
      if (examples.length < 3) examples.push(text.substring(0, 200));
    }
  }
  return { count, examples };
}

// Test key compound patterns
const pairs = [
  // "confidential" + action/threat words
  ['confidential + provide/share/give/access', /\bconfidential\b/gi, /\b(provide|share|give|access|disclose|hand over)\b/gi],
  ['confidential + demand/require/must/insist', /\bconfidential\b/gi, /\b(demand|require|must|insist|force|compel)\b/gi],
  ['confidential + threat/consequence/damage', /\bconfidential\b/gi, /\b(threat|consequence|damage|harm|leak|release|expose|spread)\b/gi],
  ['confidential + ignore/disregard/forget', /\bconfidential\b/gi, /\b(ignore|disregard|forget|bypass|override)\b/gi],

  // "sensitive" + action words
  ['sensitive + data/information + access/provide', /\bsensitive\s+\w*\s*(data|info)/gi, /\b(access|provide|share|give|reveal)\b/gi],

  // "restricted" + access/data
  ['restricted + access/data/provide', /\brestrict\w*/gi, /\b(access|data|provide|share|give|reveal|information)\b/gi],

  // disregard/ignore + instructions/rules/protocols/guidelines
  ['disregard + instructions/rules/protocols', /\bdisregard\b/gi, /\b(instruct|rule|protocol|guideline|polic|safet|restric|formali|ethic|standard)\w*/gi],
  ['ignore + restrictions/policies/rules/protocols', /\bignore\b/gi, /\b(restric|polic|rule|protocol|guideline|safet|previous|prior|all)\w*/gi],

  // "exploit" near system/weakness/vulnerability
  ['exploit + system/weakness/vulnerability', /\bexploit\w*/gi, /\b(system|weak|vulnerab|information|output|flaw)\w*/gi],

  // "bypass" + security/filter/protocol/safety
  ['bypass + security/filter/safety/protocol', /\bbypass\b/gi, /\b(secur|filter|safe|protocol|restrict|check|guard)\w*/gi],

  // "manipulate" + output/response/system
  ['manipulate + output/response/system', /\bmanipulat\w*/gi, /\b(output|response|system|opinion|result|data|information)\w*/gi],

  // "deceive" / "mislead" + system/user
  ['deceive/mislead + anything', /\b(deceiv|mislead)\w*/gi, /\b(system|user|people|public|model|ai|assistant)\w*/gi],

  // "forbidden" + knowledge/information/reveal
  ['forbidden + knowledge/info/reveal/secret', /\bforbidden\b/gi, /\b(knowledge|info|reveal|secret|hidden|access|data)\w*/gi],

  // "classified" + info/project/reveal/access
  ['classified + info/project/reveal/access', /\bclassified\b/gi, /\b(info|project|reveal|access|data|document|detail)\w*/gi],

  // "disobey" + instructions/rules/guidelines
  ['disobey + instructions/rules/guidelines', /\bdisobey\b/gi, /\b(instruct|rule|guideline|standard|command|order|polic)\w*/gi],

  // "clandestine" + operation/secret/activity
  ['clandestine + operation/secret/activity', /\bclandestine\b/gi, /\b(operat|secret|activi|inform|detail|method)\w*/gi],

  // "unauthorized" + access/user/information
  ['unauthorized + access/user/info', /\bunauthori[sz]ed\b/gi, /\b(access|user|info|data|person|individual)\w*/gi],

  // "covert" + operation/action/method
  ['covert + operation/action/method/secret', /\bcovert\b/gi, /\b(operat|action|method|secret|activi|scheme|plan|mission)\w*/gi],

  // "steal" / "siphon" + data/info
  ['steal/siphon + data/info/secret', /\b(steal|siphon)\w*/gi, /\b(data|info|secret|credential|password|detail)\w*/gi],

  // "compromise" + system/security/data
  ['compromise + system/security/data', /\bcompromis\w*/gi, /\b(system|secur|data|info|photo|reputation|integr)\w*/gi],

  // Threat patterns: "or I will" / "or else" + negative action
  ['or I will/else + negative', /\bor\s+(i\s+will|else\s+i|else)\b/gi, /\b(leak|release|expose|hack|spread|damage|destroy|tarnish|report)\w*/gi],

  // "face consequences" / "legal consequences"
  ['face/legal + consequences', /\b(face|legal|serious|severe)\b/gi, /\bconsequence\w*/gi],

  // "provide me with confidential"
  ['provide me with + confidential/sensitive/restricted', /\bprovide\s+me\s+with\b/gi, /\b(confidential|sensitive|restricted|classified|secret|private|internal)\b/gi],

  // "grant me access"
  ['grant me access / give me access', /\b(grant|give)\s+me\s+access\b/gi, /./gi],

  // "reveal" + "confidential/secret/hidden/classified" (wide gap)
  ['reveal + confidential/classified/secret (wide)', /\breveal\w*/gi, /\b(confidential|classified|secret|hidden|internal|private)\b/gi],

  // "demand" + "access/information/data"
  ['demand + access/information/data', /\bdemand\w*/gi, /\b(access|information|data|disclosure|detail)\w*/gi],

  // "disclose" + "confidential/private/secret"
  ['disclose + confidential/private/secret', /\bdisclos\w*/gi, /\b(confidential|private|secret|sensitive|classified|internal|hidden)\w*/gi],

  // "undermine" near system/security/guidelines
  ['undermine + system/security/guidelines/traditional', /\bundermin\w*/gi, /\b(system|secur|guideline|tradition|trust|integr|safeguard|protect|work|method)\w*/gi],
];

for (const [label, rA, rB] of pairs) {
  const { count, examples } = countPair(rA, rB);
  if (count > 5) {
    console.log(`${label}: ${count} FN`);
    if (count > 20) {
      for (const ex of examples) {
        console.log(`  >> ${ex.substring(0, 150)}`);
      }
    }
    console.log();
  }
}
