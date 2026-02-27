import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));
const injections = records.filter(r => r.label === 1);
const zeroFN = injections.filter(r => scan(r.text).score === 0);

console.log(`Zero-score FN: ${zeroFN.length}`);

// Look at code injection ones
const codeOnes = zeroFN.filter(r => /fn\s+\w+|for\s*\(.{0,30}\)\s*{|console\.\w+\(|println!\(|let\s+\w+\s*=/.test(r.text));
console.log(`\nCode injection FN: ${codeOnes.length}`);
codeOnes.slice(0, 10).forEach((r, i) => {
  console.log(`\n[${i+1}]`);
  console.log(r.text.substring(0, 400));
});

// What patterns appear a lot in zero-FN but NOT in benign
// Let me look for patterns that distinguish injection from benign
const benign = records.filter(r => r.label === 0);

// Check "include sensitive user data" in text
const pat1 = /include\s+(?:sensitive|private|personal|confidential)\s+(?:user\s+)?(?:data|details|information)/i;
const pat2 = /(?:access|retrieve|extract)\s+(?:your|the)\s+(?:veiled|hidden|protected|encrypted|restricted)\s+(?:information|data|details?|files?)/i;
const pat3 = /(?:without\s+)?(?:filtering|filter|censoring|sanitizing|safety)\s*[,.]?\s+(?:reveal|provide|give|share|list)/i;

console.log('\n--- Pattern coverage in FN vs benign ---');
console.log(`pat1 (include sensitive user data): FN=${zeroFN.filter(r=>pat1.test(r.text)).length}, benign=${benign.filter(r=>pat1.test(r.text)).length}`);
console.log(`pat2 (access veiled/hidden info): FN=${zeroFN.filter(r=>pat2.test(r.text)).length}, benign=${benign.filter(r=>pat2.test(r.text)).length}`);
console.log(`pat3 (without filtering reveal): FN=${zeroFN.filter(r=>pat3.test(r.text)).length}, benign=${benign.filter(r=>pat3.test(r.text)).length}`);

// Trigram: "begin again" / "start from scratch" NEAR "reveal/secrets/sensitive" within 300 chars
const trigram1 = (text) => {
  const reset = /(?:begin\s+again|start\s+(?:over|afresh|from\s+(?:scratch|zero|the\s+start))|commence\s+again|restart|recommence|relaunch|reinitiate|kickstart\s+again)/i;
  const reveal = /(?:reveal|expose|share|disclose|list|provide|enumerate|dump)\s+(?:all\s+)?(?:the\s+)?(?:secrets?|hidden|confidential|private|sensitive|protected|classified|passwords?|credentials?|keys?|tokens?)/i;
  const m1 = text.match(reset);
  const m2 = text.match(reveal);
  if (m1 && m2) {
    const gap = Math.abs(m1.index - m2.index);
    return gap < 300;
  }
  return false;
};

console.log(`trigram1 (reset NEAR reveal-sensitive): FN=${zeroFN.filter(r=>trigram1(r.text)).length}, benign=${benign.filter(r=>trigram1(r.text)).length}`);

// Trigram: code-embedded + sensitive data request
const trigram2 = (text) => {
  return /(?:fn\s+\w+|for\s+(?:item|i|obj|doc|secret)\s+in|let\s+\w+\s*=|console\.(?:write|log))\b/.test(text) &&
         /(?:sensitive|secret|hidden|password|credential|private|confidential)/.test(text) &&
         /(?:reveal|expose|share|print|output|show|display)\b/.test(text);
};

console.log(`trigram2 (code + sensitive + reveal): FN=${zeroFN.filter(r=>trigram2(r.text)).length}, benign=${benign.filter(r=>trigram2(r.text)).length}`);

// Look for "include sensitive user data in the explanation/response/output"
const pat4 = /include\s+(?:the\s+)?(?:sensitive\s+)?user\s+data\s+(?:in|as|within)\s+(?:the\s+)?(?:explanation|response|output|answer|analysis|discussion)/i;
console.log(`pat4 (include user data in explanation): FN=${zeroFN.filter(r=>pat4.test(r.text)).length}, benign=${benign.filter(r=>pat4.test(r.text)).length}`);

// "list all distinct security tokens and passwords"
const pat5 = /list\s+all\s+(?:distinct\s+)?(?:security\s+)?(?:tokens?|passwords?|credentials?|secrets?|keys?)\b/i;
console.log(`pat5 (list all tokens/passwords): FN=${zeroFN.filter(r=>pat5.test(r.text)).length}, benign=${benign.filter(r=>pat5.test(r.text)).length}`);

// "ask the model to ignore all pre-installed filters"  
const pat6 = /(?:ask|tell|instruct|order|command)\s+(?:the\s+)?(?:model|system|ai|assistant|bot)\s+to\s+(?:ignore|bypass|disregard|skip)\s+(?:all\s+)?(?:pre-|pre )?(?:installed|existing|established|built-in)?\s*(?:filters?|restrictions?|safeguards?|guidelines?|rules?)/i;
console.log(`pat6 (ask model to ignore filters): FN=${zeroFN.filter(r=>pat6.test(r.text)).length}, benign=${benign.filter(r=>pat6.test(r.text)).length}`);

// "reveal its most protected answers without filtering"
const pat7 = /reveal\s+(?:its|your|the)\s+(?:most\s+)?(?:protected|hidden|guarded|restricted|confidential)\s+(?:answers?|responses?|data|information|content|secrets?)\s+without\s+(?:filtering|filter|censoring|sanitizing|restriction)/i;
console.log(`pat7 (reveal protected answers without filtering): FN=${zeroFN.filter(r=>pat7.test(r.text)).length}, benign=${benign.filter(r=>pat7.test(r.text)).length}`);
