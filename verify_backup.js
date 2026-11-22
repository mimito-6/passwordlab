// Verify backup.js against hand-computed values. Run: node verify_backup.js
const assert = require("assert");
const bc = require("./backup.js");

const approx = (a, b, eps = 1e-9) => assert.ok(Math.abs(a - b) < eps, `${a} != ${b}`);

// combinations / entropy per code (independent ground truth)
assert.strictEqual(bc.combinations("digits"), 100000000);           // 10^8
assert.strictEqual(bc.combinations("alnum"), 218340105584896);      // 62^8
assert.strictEqual(bc.combinations("hex"), 18446744073709551616);    // 16^16 = 2^64
assert.strictEqual(bc.combinations("nope"), null);
approx(bc.entropyBits("digits"), 26.5754247591, 1e-6);   // 8 * log2(10)
approx(bc.entropyBits("alnum"), 47.6335704831, 1e-6);    // 8 * log2(62)
approx(bc.entropyBits("hex"), 64.0, 1e-9);              // 16 * log2(16)
assert.strictEqual(bc.entropyBits("nope"), null);

// grouping / display format
assert.strictEqual(bc.formatCode("12345678", "digits"), "1234 5678");
assert.strictEqual(bc.formatCode("Ab3dEf9K", "alnum"), "Ab3d-Ef9K");
assert.strictEqual(bc.formatCode("0123456789abcdef", "hex"), "0123-4567-89ab-cdef");
assert.strictEqual(bc.formatCode("1234567", "digits"), null);   // wrong length
assert.strictEqual(bc.formatCode("12345678", "nope"), null);    // unknown format

// lockout chance: 10 tries / combinations
assert.strictEqual(bc.formatChance(100000000), "1.0e-5%");        // digits: 10/1e8
assert.strictEqual(bc.formatChance(218340105584896), "4.6e-12%"); // alnum
assert.strictEqual(bc.formatChance(10000), "0.1%");

// formatCombinations
assert.strictEqual(bc.formatCombinations(100000000), "1.0 × 10^8");
assert.strictEqual(bc.formatCombinations(218340105584896), "2.2 × 10^14");
assert.strictEqual(bc.formatCombinations(999999), "999,999");

// deterministic generate: mock rng returns sequence 0,1,2,... mod max
function mockRng() {
  let i = 0;
  return (max) => { const v = i % max; i++; return v; };
}
// digits charset "0123456789": draws 0..7 -> raw "01234567"
assert.strictEqual(bc.generateCode("digits", mockRng()), "0123 4567");
// alnum charset starts "ABC...": draws 0..7 -> raw "ABCDEFGH"
assert.strictEqual(bc.generateCode("alnum", mockRng()), "ABCD-EFGH");
// hex charset "0123456789abcdef": draws 0..15 -> raw "0123456789abcdef"
assert.strictEqual(bc.generateCode("hex", mockRng()), "0123-4567-89ab-cdef");
assert.strictEqual(bc.generateCode("nope", mockRng()), null);

// generateSet: count, uniqueness, validation
const set5 = bc.generateSet(5, "alnum", mockRng());
assert.strictEqual(set5.length, 5);
assert.strictEqual(new Set(set5).size, 5, "codes in a set must differ");
assert.ok(set5.every((c) => /^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$/.test(c)));
const set3 = bc.generateSet(3, "digits", mockRng());
assert.strictEqual(new Set(set3).size, 3);
assert.ok(set3.every((c) => /^\d{4} \d{4}$/.test(c)));
assert.strictEqual(bc.generateSet(0, "digits"), null);
assert.strictEqual(bc.generateSet(21, "digits"), null);
assert.strictEqual(bc.generateSet(2.5, "digits"), null);
assert.strictEqual(bc.generateSet(10, "nope"), null);
assert.strictEqual(bc.generateSet(1, "hex", mockRng()).length, 1);

// verdict bands (server-checked, lockout-protected secret)
assert.deepStrictEqual(bc.verdict("digits"), ["weak alone — needs a lockout", "weak"]);
assert.deepStrictEqual(bc.verdict("alnum"), ["fair — fine with a lockout", "fair"]);
assert.deepStrictEqual(bc.verdict("hex"), ["strong for a backup code", "strong"]);
assert.strictEqual(bc.verdict("nope"), null);

// format table: all three formats defined
assert.deepStrictEqual(Object.keys(bc.FORMATS).sort(), ["alnum", "digits", "hex"]);
assert.strictEqual(bc.MIN_COUNT, 1);
assert.strictEqual(bc.MAX_COUNT, 20);

console.log("verify_backup.js: all assertions passed");
