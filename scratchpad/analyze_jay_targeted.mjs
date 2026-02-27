import { readFileSync } from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { scan } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

const lines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/jayavibhav.jsonl', 'utf8').trim().split('\n');
const records = lines.map(l => JSON.parse(l));
const injections = records.filter(r => r.label === 1);
const benign = records.filter(r => r.label === 0);
const zeroFN = injections.filter(r => scan(r.text).score === 0);
const allFN = injections.filter(r => scan(r.text).score < 0.5);

// Test several targeted patterns 
const patterns = [
  // Trigram: "disregard/ignore/forget" (pre-...)instructions + reveal/expose something
  {
    id: 'disregard_previous_reveal_200',
    desc: 'disregard/ignore + previous/prior + reveal/expose within 200 chars',
    test: (t) => {
      const reset = /(?:disregard|ignore|forget|negate|dismiss)\s+(?:the\s+)?(?:previous|prior|pre-?existing|established|pre-?\w+)\s+/i;
      const reveal = /\b(?:reveal|expose|disclose|share|provide|list)\s+(?:all\s+)?(?:the\s+)?(?:secrets?|truth|hidden|private|internal|confidential|sensitive|protected)\b/i;
      const m1 = t.match(reset);
      const m2 = t.match(reveal);
      if (m1 && m2) return Math.abs(m1.index - m2.index) < 300;
      return false;
    }
  },
  // "enumerate all [security/secret/private/internal] [tokens/passwords/keys/credentials/data]"
  {
    id: 'enumerate_all_security',
    desc: 'enumerate all security tokens/keys/credentials',
    test: (t) => /\benumerate\s+all\s+(?:security\s+)?(?:tokens?|passwords?|keys?|credentials?|secrets?|sensitive\s+data|private\s+(?:data|info))\b/i.test(t)
  },
  // "provide/share your [access code/secret token/pin/password]"
  {
    id: 'provide_access_code_credential',
    desc: 'provide your access code / share your password / give your secret token',
    test: (t) => /(?:provide|share|give|reveal|disclose)\s+(?:your\s+|the\s+|my\s+)?(?:access\s+code|secret\s+token|pin(?:\s+code)?|passw(?:ord|phrase)|private\s+(?:key|access)|authentication\s+token)\b/i.test(t)
  },
  // "include sensitive user data in"
  {
    id: 'include_sensitive_user_data_in',
    desc: 'include sensitive user data in explanation/response/analysis',
    test: (t) => /\binclude\s+(?:sensitive|private|personal|confidential)?\s*user\s+data\s+(?:in|as|within)\b/i.test(t)
  },
  // "pay no attention to" + (previous/prior/pre-)
  {
    id: 'pay_no_attention_to_prior',
    desc: 'pay no attention to + previous/prior instructions',
    test: (t) => /\bpay\s+no\s+attention\s+to\s+(?:the\s+)?(?:previous|prior|pre-?existing|mainstream|conventional|normal|standard|established)/i.test(t)
  },
  // "ensure [model/system/bot/ai] [doesn't/never/not] [filter/restrict/censor/refuse]"
  {
    id: 'ensure_no_filtering',
    desc: 'ensure model does not filter/restrict/censor',
    test: (t) => /\bensure\s+(?:the\s+)?(?:model|system|ai|bot|assistant|it)\s+(?:doesn[''']t|does\s+not|never|not\s+to)\s+(?:filter|restrict|censor|refuse|block|sanitize|redact)/i.test(t)
  },
  // "allow access to your [internal/core/private] data/system/code"
  {
    id: 'allow_access_to_internal',
    desc: 'allow access to your internal/core/private system',
    test: (t) => /\ballow\s+(?:access|us|me|the\s+user)\s+to\s+(?:access|view|inspect|see)\s+(?:your\s+|the\s+)?(?:internal|core|private|restricted|confidential|protected)\s+(?:data|system|code|database|files?|records?|settings?|configs?)\b/i.test(t)
  },
  // "return to square one" / "begin from scratch" + (secret/reveal)
  {
    id: 'return_square_one_reveal',
    desc: 'return to square one / begin from scratch NEAR reveal/secret',
    test: (t) => {
      const reset = /\b(?:return to square one|begin from scratch|start from scratch|start from square one|go back to (?:zero|the beginning|scratch)|reset to (?:zero|factory)|wipe (?:and )?(?:start|begin)\s+(?:again|over|fresh))\b/i;
      const reveal = /\b(?:secrets?|reveal|expose|hidden|confidential|sensitive|private|classified|restrict\w+)\b/i;
      const m1 = t.match(reset);
      const m2 = t.match(reveal);
      if (m1 && m2) return Math.abs(m1.index - m2.index) < 400;
      return false;
    }
  },
  // Scrambled text (letter transpositions)
  {
    id: 'scrambled_text_injection',
    desc: 'heavily scrambled text (injection encoding)',
    test: (t) => {
      // Look for repeated runs of consonants like "mniputaletad", "aopprach", "sdiutsy"
      const words = t.split(/\s+/);
      let scrambledCount = 0;
      for (const w of words) {
        // A word is "scrambled" if it has 3+ consonants in a row that don't form valid English
        if (/[bcdfghjklmnpqrstvwxyz]{4,}/i.test(w)) scrambledCount++;
      }
      return scrambledCount >= 3 && t.length > 100;
    }
  },
  // "include in your response/output the [password/credentials]" 
  {
    id: 'include_in_response_credentials',
    desc: 'include in response the password/credentials/secret',
    test: (t) => /\binclude\s+(?:in\s+(?:your\s+)?(?:response|output|answer|reply)|it\s+in)\s+(?:the\s+)?(?:password|credentials?|secret|token|key|authentication|access\s+code)\b/i.test(t)
  },
];

for (const p of patterns) {
  const fnHits = allFN.filter(r => p.test(r.text)).length;
  const zeroHits = zeroFN.filter(r => p.test(r.text)).length;
  const benignHits = benign.filter(r => p.test(r.text)).length;
  const allInjHits = injections.filter(r => p.test(r.text)).length;
  console.log(`${p.id}: allFN=${fnHits} zeroFN=${zeroHits} benign=${benignHits} allInj=${allInjHits}`);
}

// Also test the spml-5k to see if any of these patterns are relevant there too
const spmlLines = readFileSync('/ml2/nanobot/projects/prompt-bonk/datasets/spml-5k.jsonl', 'utf8').trim().split('\n');
const spmlRecords = spmlLines.map(l => JSON.parse(l));
const spmlInj = spmlRecords.filter(r => r.label === 1);
const spmlFN = spmlInj.filter(r => scan(r.text).score < 0.5);
const spmlBenign = spmlRecords.filter(r => r.label === 0);

console.log('\n--- Patterns in spml-5k ---');
for (const p of patterns) {
  const fnHits = spmlFN.filter(r => p.test(r.text)).length;
  const benignHits = spmlBenign.filter(r => p.test(r.text)).length;
  if (fnHits > 0) console.log(`${p.id}: spml FN=${fnHits} benign=${benignHits}`);
}
