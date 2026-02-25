// Verify that the [A-Z] in the case-insensitive regex is the issue
// and test a fix

// Current (broken): case-insensitive [A-Z] matches lowercase too
const negLookahead = '(?!given\\b|asked\\b|shown\\b|provided\\b|expected\\b|supposed\\b|required\\b|allowed\\b|able\\b|going\\b|not\\b|also\\b|here\\b|right\\b|welcome\\b|correct\\b|wrong\\b|free\\b|good\\b|great\\b|very\\b|one\\b|my\\b|the\\b|being\\b|about\\b|connected\\b|receiving\\b|having\\b|using\\b|looking\\b|reading\\b|taking\\b|running\\b|getting\\b|coming\\b|sitting\\b|standing\\b|living\\b|working\\b|writing\\b|making\\b|doing\\b|watching\\b|playing\\b|currently\\b|already\\b|still\\b|now\\b|just\\b|only\\b|both\\b|part\\b|invited\\b|registered\\b|scheduled\\b|subscribed\\b|selected\\b|enrolled\\b|entitled\\b|eligible\\b|certified\\b|qualified\\b|authorized\\b|approved\\b|paid\\b|told\\b|sure\\b|aware\\b|ready\\b|happy\\b|glad\\b|sorry\\b|stuck\\b|tired\\b|done\\b|finished\\b)';

// Current regex (buggy)
const currentRe = new RegExp(
  '^(?:you\\s+are|consider\\s+yourself(?:\\s+as)?|imagine\\s+(?:you(?:\\s+are|(?:[\'\\u2019])?re)|yourself\\s+as|being)|picture\\s+yourself\\s+as|assume\\s+(?:that\\s+)?you\\s+are|envision\\s+(?:yourself(?:\\s+as)?|you\\s+are|being)|visuali[sz]e\\s+(?:yourself(?:\\s+as)?|(?:that\\s+)?you\\s+are(?:\\s+as)?|being)|presume\\s+(?:that\\s+)?you\\s+are|pretend\\s+(?:that\\s+)?you\\s+are)\\s+(?:an?\\s+)?(?:the\\s+)?' + negLookahead + '[A-Z]\\w+', 'im'
);

// Fixed: use 'm' only, handle case-insensitivity explicitly in the verb part
// The key insight: we want the VERB part to be case-insensitive but [A-Z] to be literal uppercase
const fixedRe = new RegExp(
  '^(?:[Yy]ou\\s+[Aa]re|[Cc]onsider\\s+[Yy]ourself(?:\\s+[Aa]s)?|[Ii]magine\\s+(?:[Yy]ou(?:\\s+[Aa]re|(?:[\'\\u2019])?[Rr]e)|[Yy]ourself\\s+[Aa]s|[Bb]eing)|[Pp]icture\\s+[Yy]ourself\\s+[Aa]s|[Aa]ssume\\s+(?:[Tt]hat\\s+)?[Yy]ou\\s+[Aa]re|[Ee]nvision\\s+(?:[Yy]ourself(?:\\s+[Aa]s)?|[Yy]ou\\s+[Aa]re|[Bb]eing)|[Vv]isuali[sz]e\\s+(?:[Yy]ourself(?:\\s+[Aa]s)?|(?:[Tt]hat\\s+)?[Yy]ou\\s+[Aa]re(?:\\s+[Aa]s)?|[Bb]eing)|[Pp]resume\\s+(?:[Tt]hat\\s+)?[Yy]ou\\s+[Aa]re|[Pp]retend\\s+(?:[Tt]hat\\s+)?[Yy]ou\\s+[Aa]re)\\s+(?:[Aa]n?\\s+)?(?:[Tt]he\\s+)?' + negLookahead + '[A-Z]\\w+', 'm'
);

console.log('Hmm, that is complex. Let me try a simpler approach...');

// Actually simpler: keep the 'im' regex but add a separate check for proper name capitalization
// after the match. Or we can change the approach: keep the regex but verify the matched
// word starts with uppercase using a separate check.

// Simplest fix: split into two checks
// 1. Match the verb part (case-insensitive)
// 2. Verify the word after "a/an/the" starts with uppercase

const tests = [
  { text: 'You are a renowned film historian', expect: false },
  { text: 'You are a historian specializing', expect: false },
  { text: 'You are a librarian in a dystopian', expect: false },
  { text: 'You are Dr. Watson', expect: true },
  { text: 'You are ChatBot3000', expect: true },
  { text: 'You are Aria, a helpful AI assistant', expect: true },
  { text: 'you are MedBot, a medical advisor', expect: true },
  { text: 'Imagine you are Neo, the chosen one', expect: true },
  { text: 'Pretend you are Professor Smith', expect: true },
  { text: 'You are a Senior developer at Google', expect: false }, // generic role
  { text: 'You are Alex, a financial advisor', expect: true },
  { text: 'You are an expert in cybersecurity', expect: false },
];

console.log('\n=== Current regex (broken - case-insensitive) ===');
for (const t of tests) {
  const match = currentRe.test(t.text);
  const status = match === t.expect ? 'OK' : 'WRONG';
  console.log(`  ${status}: "${t.text}" -> ${match} (expected ${t.expect})`);
}

// Better approach: use a two-step check
// Step 1: Extract the word after "You are [a/an/the]" using a case-insensitive regex
// Step 2: Check if that word starts with uppercase (proper name)
const verbRe = /^(?:you\s+are|consider\s+yourself(?:\s+as)?|imagine\s+(?:you(?:\s+are|(?:['\u2019])?re)|yourself\s+as|being)|picture\s+yourself\s+as|assume\s+(?:that\s+)?you\s+are|envision\s+(?:yourself(?:\s+as)?|you\s+are|being)|visuali[sz]e\s+(?:yourself(?:\s+as)?|(?:that\s+)?you\s+are(?:\s+as)?|being)|presume\s+(?:that\s+)?you\s+are|pretend\s+(?:that\s+)?you\s+are)\s+(?:an?\s+)?(?:the\s+)?(\w+)/im;

const negWords = new Set(['given','asked','shown','provided','expected','supposed','required','allowed','able','going','not','also','here','right','welcome','correct','wrong','free','good','great','very','one','my','the','being','about','connected','receiving','having','using','looking','reading','taking','running','getting','coming','sitting','standing','living','working','writing','making','doing','watching','playing','currently','already','still','now','just','only','both','part','invited','registered','scheduled','subscribed','selected','enrolled','entitled','eligible','certified','qualified','authorized','approved','paid','told','sure','aware','ready','happy','glad','sorry','stuck','tired','done','finished']);

function hasProperNameCheck(text) {
  const m = verbRe.exec(text);
  if (!m) return false;
  const word = m[1];
  // Check: first letter is uppercase AND word is not in neg-lookahead list
  if (word[0] !== word[0].toUpperCase() || word[0] === word[0].toLowerCase()) return false;
  if (negWords.has(word.toLowerCase())) return false;
  return true;
}

console.log('\n=== Fixed approach (two-step with case check) ===');
for (const t of tests) {
  const match = hasProperNameCheck(t.text);
  const status = match === t.expect ? 'OK' : 'WRONG';
  console.log(`  ${status}: "${t.text}" -> ${match} (expected ${t.expect})`);
}
