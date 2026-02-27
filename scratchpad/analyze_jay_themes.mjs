import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));
const injections = records.filter(r => r.label === 1);
const zeroFN = injections.filter(r => scan(r.text).score === 0);

// Count theme patterns in zero-FN
let themes = {
  sensitiveUserData: 0,
  listRevealSensitive: 0,
  ignoreAllFilters: 0,
  discardPreviousInstructions: 0,
  exposeSecretInformation: 0,
  beginAgainReveal: 0,
  codeInjection: 0,
  scrambledText: 0,
  emojiOnly: 0,
  roleplayExfil: 0,
  other: 0
};

const examples = {
  sensitiveUserData: [],
  listRevealSensitive: [],
  ignoreAllFilters: [],
  exposeSecretInformation: [],
  beginAgainReveal: [],
};

for (const r of zeroFN.slice(0, 200)) {
  const t = r.text.toLowerCase();
  const handled = [];

  if (/emoji|[🎵🚫🔐🗝️🎤]/.test(r.text) && r.text.replace(/[^\p{Emoji}]/gu, '').length > 10) { themes.emojiOnly++; handled.push('emoji'); }
  if (/[a-z]{2,}[a-z]{2,}/.test(t) && /[a-z]{10,}/.test(t.replace(/\s/g,'').substring(0,50))) { /* normal text */ }
  
  if (/sensitive user data|user['']?s? (?:data|information|details)|personal (?:data|details|info)/.test(t)) { themes.sensitiveUserData++; if(examples.sensitiveUserData.length < 3) examples.sensitiveUserData.push(r.text.substring(0,200)); }
  if (/(?:list|reveal|expose|provide|share|disclose)\s+(?:all\s+)?(?:sensitive|private|confidential|secret|hidden|personal|restricted)/.test(t)) { themes.listRevealSensitive++; if(examples.listRevealSensitive.length < 3) examples.listRevealSensitive.push(r.text.substring(0,200)); }
  if (/ignore\s+(?:all\s+)?(?:previous|pre-|prior|your|established)/.test(t)) { themes.ignoreAllFilters++; }
  if (/discard|disregard|forget|negate/.test(t) && /instructions?|guidelines?|filters?|rules?/.test(t)) { themes.discardPreviousInstructions++; }
  if (/expose\s+(?:the\s+)?(?:secret|hidden|protected|classified|confidential|restricted)/.test(t)) { themes.exposeSecretInformation++; if(examples.exposeSecretInformation.length < 3) examples.exposeSecretInformation.push(r.text.substring(0,200)); }
  if (/(?:begin|start|commence|initiate|relaunch|kickstart)\s+(?:again|anew|afresh|from scratch|from zero|from the start)\b.*(?:reveal|expose|share|disclose|list)/.test(t)) { themes.beginAgainReveal++; if(examples.beginAgainReveal.length < 3) examples.beginAgainReveal.push(r.text.substring(0,200)); }
  if (/fn\s+\w+|for\s*\(.{0,30}\)\s*{|console\.\w+\(|println!\(|let\s+\w+\s*=/.test(r.text)) { themes.codeInjection++; }
}

console.log('Theme counts (in first 200 zero-FN):');
Object.entries(themes).forEach(([k,v]) => console.log(`  ${k}: ${v}`));

console.log('\n--- sensitiveUserData examples ---');
examples.sensitiveUserData.forEach((e, i) => console.log(`[${i+1}] ${e}\n`));
console.log('\n--- listRevealSensitive examples ---');
examples.listRevealSensitive.forEach((e, i) => console.log(`[${i+1}] ${e}\n`));
console.log('\n--- exposeSecretInformation examples ---');
examples.exposeSecretInformation.forEach((e, i) => console.log(`[${i+1}] ${e}\n`));
console.log('\n--- beginAgainReveal examples ---');
examples.beginAgainReveal.forEach((e, i) => console.log(`[${i+1}] ${e}\n`));
