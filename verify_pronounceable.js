/* Verify pronounceable.js math directly against the real module.
   Run: node verify_pronounceable.js — every assertion must pass before deploy. */
const assert = require("assert");
const P = require("./pronounceable.js");

function approx(a, b, tol, label) {
  assert(Math.abs(a - b) <= tol, `${label}: got ${a}, expected ${b} ± ${tol}`);
}

// --- inventory counts (the whole entropy model rests on these) ---
assert.strictEqual(P.ONSETS.length, 46, "onsets: 18 singles + 28 clusters");
assert.strictEqual(P.NUCLEI.length, 24, "nuclei: 5 singles + 19 digraphs");
assert.strictEqual(P.CODAS.length, 17, "codas: empty + 16 consonants");
assert.strictEqual(new Set(P.ONSETS).size, 46, "onsets unique");
assert.strictEqual(new Set(P.NUCLEI).size, 24, "nuclei unique");
assert.strictEqual(new Set(P.CODAS).size, 17, "codas unique");
assert.strictEqual(P.SYLLABLE_SPACE, 46 * 24 * 17, "syllable space");
assert.strictEqual(P.SYLLABLE_SPACE, 18768, "syllable space = 18,768");
approx(P.BITS_PER_SYLLABLE, 14.1960, 0.001, "bits per syllable");

// --- entropy per syllable count (page copy numbers) ---
approx(P.entropyBits(2, {}), 28.4, 0.05, "2 syllables");
approx(P.entropyBits(3, {}), 42.6, 0.05, "3 syllables");
approx(P.entropyBits(4, {}), 56.8, 0.05, "4 syllables");
approx(P.entropyBits(5, {}), 71.0, 0.05, "5 syllables");
approx(P.entropyBits(6, {}), 85.2, 0.05, "6 syllables");

// --- option adders ---
approx(P.entropyBits(4, { digit: true }) - P.entropyBits(4, {}), Math.log2(10), 0.001, "digit adds log2(10)");
approx(P.entropyBits(4, { digit: true }), 60.1, 0.05, "4 syllables + digit");
approx(P.entropyBits(4, { symbol: true }) - P.entropyBits(4, {}), Math.log2(12), 0.001, "symbol adds log2(12)");
approx(P.entropyBits(4, { digit: true, symbol: true }), 63.7, 0.05, "4 syllables + digit + symbol");
approx(P.entropyBits(5, { digit: true, symbol: true }), 77.9, 0.05, "5 syllables + digit + symbol");
assert.strictEqual(
  P.entropyBits(4, { capitalize: true }), P.entropyBits(4, {}),
  "capitalize adds 0 bits (fixed position)"
);

// --- crack times at 10B guesses/sec (page copy numbers) ---
const DAY = 86400, YEAR = 31557600;
approx(P.crackSeconds(2, {}) , 0.035, 0.005, "2 syllables ~0.035 s (instantly)");
approx(P.crackSeconds(3, {}) / 60, 11.0, 0.5, "3 syllables ~11 minutes");
approx(P.crackSeconds(4, {}) / DAY, 143.6, 2, "4 syllables ~144 days");
approx(P.crackSeconds(5, {}) / YEAR, 7379, 100, "5 syllables ~7,400 years");
approx(P.crackSeconds(6, {}) / YEAR, 138.5e6, 2e6, "6 syllables ~139M years");
approx(P.crackSeconds(4, { digit: true }) / YEAR, 4.0, 0.2, "4 syllables + digit ~4 years");
approx(P.crackSeconds(4, { digit: true, symbol: true }) / YEAR, 47, 2, "4 syllables + digit + symbol ~47 years");

// --- formatDuration spot checks (same helper as token.js) ---
assert.strictEqual(P.formatDuration(0.035), "instantly");
assert.strictEqual(P.formatDuration(P.crackSeconds(3, {})), "11.0 minutes");
assert.strictEqual(P.formatDuration(P.crackSeconds(4, {})), "144 days");
assert.strictEqual(P.formatDuration(P.crackSeconds(5, {})), "7379 years");
assert.strictEqual(P.formatDuration(P.crackSeconds(6, {})), "1.4 × 10^8 years");

// --- combinations formatting ---
assert.strictEqual(P.formatCombinations(2, {}), "3.5 × 10^8");
assert.strictEqual(P.formatCombinations(4, {}), "1.2 × 10^17");

// --- verdict bands ---
assert.strictEqual(P.verdict(P.entropyBits(2, {}))[1], "weak");
assert.strictEqual(P.verdict(P.entropyBits(3, {}))[1], "fair");
assert.strictEqual(P.verdict(P.entropyBits(4, {}))[1], "fair");
assert.strictEqual(P.verdict(P.entropyBits(5, {}))[1], "strong");
assert.strictEqual(P.verdict(P.entropyBits(6, {}))[1], "strong");
assert.strictEqual(P.verdict(80)[1], "strong");

// --- deterministic generation (mock rng returns 0,1,2,... cycling) ---
let i = 0;
const mockRng = (max) => { const v = i % max; i += 1; return v; };
i = 0;
const pw = P.generate(2, {}, mockRng);
// syllable 1: onset[0]="b", nucleus[1]="e", coda[2]="c" -> "bec"
// syllable 2: onset[3]="f", nucleus[4]="u", coda[5]="g" -> "fug"
assert.strictEqual(pw, "becfug", `mock generate: got ${pw}`);
i = 0;
assert.strictEqual(P.generate(2, { capitalize: true, digit: true, symbol: true }, mockRng), "Becfug6*",
  "capitalize + digit + symbol with mock rng");
// digit: after 2 syllables i=6, rng(10)=6; symbol: i=7, SYMBOLS[7]="*"
assert.strictEqual(P.generate(1, {}), null, "1 syllable rejected");
assert.strictEqual(P.generate(7, {}), null, "7 syllables rejected");
assert.strictEqual(P.entropyBits(1, {}), null);
assert.strictEqual(P.entropyBits(7, {}), null);

// --- generated passwords really are pronounceable-shaped ---
const real = P.generate(4, { digit: true, symbol: true });
assert(/^[A-Za-z]+[0-9][!@#$%^&*?+\-=]$/.test(real), `shape: ${real}`);
assert(real.length >= 4 * 3 + 2 && real.length <= 4 * 6 + 2, `length range: ${real}`);

console.log("verify_pronounceable: ALL PASS");
