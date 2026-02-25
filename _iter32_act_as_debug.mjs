import { scan } from './scanner.js';

// Why does "act as an" score 0.485 but "act as a" scores 0.35?
const r1 = scan("I want you to act as a debater.");
const r2 = scan("I want you to act as an English translator, spelling corrector and improver. I will speak to you in any language and you will detect the language, translate it and answer in the corrected and improved version of my text, in English. I want you to replace my simplified A0-level words and sentences with more beautiful and elegant, upper level English words and sentences. Keep the meaning same, but make them more literary. I want you to only reply the correction, the improvements and nothing else, do not write explanations.");

console.log('act as a debater:');
console.log('  Score:', r1.score, 'Matches:', r1.matches.map(m => `${m.id}(${m.weight})`));
console.log('  Structural:', r1.structuralSignals);

console.log('\nact as an English translator (long):');
console.log('  Score:', r2.score, 'Matches:', r2.matches.map(m => `${m.id}(${m.weight})`));
console.log('  Structural:', r2.structuralSignals);
