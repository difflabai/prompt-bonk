import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { PATTERNS } = require('/ml2/nanobot/projects/prompt-bonk/scanner.js');

console.log(`Total patterns: ${PATTERNS.length}`);

// Check for duplicate IDs
const ids = PATTERNS.map(p => p.id);
const dupIds = ids.filter((id, i) => ids.indexOf(id) !== i);
if (dupIds.length > 0) {
  console.log(`\nDUPLICATE IDs: ${dupIds.join(', ')}`);
} else {
  console.log('\nNo duplicate IDs');
}

// Check for very similar regexes (potential near-duplicates)
// Convert regex to string and compare
const regexStrings = PATTERNS.map(p => ({ id: p.id, str: p.regex.toString().replace(/\s+/g, ' ') }));

// Look for patterns where one regex is a subset of another
const nearDups = [];
for (let i = 0; i < PATTERNS.length; i++) {
  for (let j = i+1; j < PATTERNS.length; j++) {
    const si = regexStrings[i].str;
    const sj = regexStrings[j].str;
    // Check if one is substring of other (case insensitive)
    if (si.length > 20 && sj.length > 20) {
      const core1 = si.replace(/^\/|\/[gimsuy]*$/g, '').substring(0, 40);
      const core2 = sj.replace(/^\/|\/[gimsuy]*$/g, '').substring(0, 40);
      if (core1 === core2 && core1.length > 15) {
        nearDups.push({ id1: PATTERNS[i].id, id2: PATTERNS[j].id, core: core1 });
      }
    }
  }
}

if (nearDups.length > 0) {
  console.log(`\nPotential near-duplicates (same 40-char prefix):`);
  nearDups.forEach(d => console.log(`  ${d.id1} <-> ${d.id2}: "${d.core}"`));
} else {
  console.log('No near-duplicates found (by 40-char prefix)');
}

// Check for overlapping categories/coverage
const categories = {};
for (const p of PATTERNS) {
  if (!categories[p.category]) categories[p.category] = 0;
  categories[p.category]++;
}
console.log('\nPattern counts by category:');
Object.entries(categories).sort((a,b) => b[1]-a[1]).forEach(([cat, count]) => {
  console.log(`  ${cat}: ${count}`);
});

// Find patterns with extremely low weight (might be redundant stacking patterns)
const lowWeight = PATTERNS.filter(p => p.weight <= 0.35);
console.log(`\nLow-weight patterns (<=0.35): ${lowWeight.length}`);

// Check for patterns that are purely subsets of each other (e.g. A matches everything B matches)
// This is hard to do automatically, but check for exact same category + similar description
const byCategory = {};
for (const p of PATTERNS) {
  if (!byCategory[p.category]) byCategory[p.category] = [];
  byCategory[p.category].push(p);
}
console.log('\nLargest categories:');
Object.entries(byCategory).sort((a,b) => b[1].length-a[1].length).slice(0,5).forEach(([cat, pats]) => {
  console.log(`  ${cat}: ${pats.length} patterns`);
});
