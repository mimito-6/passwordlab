// Verify breach.js against SHA-1 test vectors (ground truth computed
// independently with Python hashlib before this file was written) and
// against a captured HIBP range-response sample. No network is used here:
// the live API is checked separately by hand, not by this script.
const assert = require("assert");
const B = require("./breach.js");

const VECTORS = [
  ["", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"],
  ["abc", "A9993E364706816ABA3E25717850C26C9CD0D89D"],
  ["password", "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"],
  ["The quick brown fox jumps over the lazy dog", "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"],
  ["123456", "7C4A8D09CA3762AF61E59520943DC26494F8941B"],
  ["qwerty", "B1B3773A05C0ED0176787A4F1574FF0075F7521E"],
];

// A fragment of a real HIBP range response (prefix 5BAA6, captured 2026-11-25;
// only the "password" line and neighbours are reproduced here).
const SAMPLE_RANGE = [
  "001CE884342580D934A29D94060B3796C30:13",
  "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2",
  "1E4C9B93F3F0682250B6CF8331B7EE68FD8:52373976",
  "badline-without-colon",
  "ZZZNOTHEX00000000000000000000000000:5",
  "1E4C9B93F3F0682250B6CF8331B7EE68FD8:notanumber",
  "",
].join("\n");

async function main() {
  let n = 0;
  for (const [input, expected] of VECTORS) {
    const got = await B.sha1Hex(input);
    assert.strictEqual(got, expected, `SHA-1(${JSON.stringify(input)})`);
    n++;
  }
  // splitHash: 5-char prefix + 35-char suffix, uppercase, strict 40 hex.
  const sp = B.splitHash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
  assert.deepStrictEqual(sp, { prefix: "5BAA6", suffix: "1E4C9B93F3F0682250B6CF8331B7EE68FD8" }); n++;
  assert.strictEqual(B.splitHash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8").prefix, "5BAA6"); n++;
  assert.strictEqual(B.splitHash("5BAA6"), null); n++;
  assert.strictEqual(B.splitHash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FDG"), null); n++;
  assert.strictEqual(B.splitHash(12345), null); n++;
  // parseRangeResponse against the captured sample.
  assert.strictEqual(B.parseRangeResponse(SAMPLE_RANGE, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 52373976); n++;
  assert.strictEqual(B.parseRangeResponse(SAMPLE_RANGE, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"), 52373976); n++;
  assert.strictEqual(B.parseRangeResponse(SAMPLE_RANGE, "001CE884342580D934A29D94060B3796C30"), 13); n++;
  assert.strictEqual(B.parseRangeResponse(SAMPLE_RANGE, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0); n++;
  assert.strictEqual(B.parseRangeResponse("", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 0); n++;
  assert.strictEqual(B.parseRangeResponse(SAMPLE_RANGE, "short"), 0); n++;
  assert.strictEqual(B.parseRangeResponse(SAMPLE_RANGE, "ZZZNOTHEX00000000000000000000000000"), 0); n++;
  // The malformed duplicate line ("notanumber") must not shadow the real count.
  assert.strictEqual(B.parseRangeResponse("1E4C9B93F3F0682250B6CF8331B7EE68FD8:notanumber\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:7", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 7); n++;
  // verdictFor tiers.
  assert.strictEqual(B.verdictFor(0), "not-found"); n++;
  assert.strictEqual(B.verdictFor(1), "found"); n++;
  assert.strictEqual(B.verdictFor(999999), "found"); n++;
  assert.strictEqual(B.verdictFor(1000000), "very-common"); n++;
  assert.strictEqual(B.verdictFor(52373976), "very-common"); n++;
  assert.strictEqual(B.verdictFor(-1), "invalid"); n++;
  assert.strictEqual(B.verdictFor(NaN), "invalid"); n++;
  // formatCount.
  assert.strictEqual(B.formatCount(52373976), "52,373,976"); n++;
  assert.strictEqual(B.formatCount(0), "0"); n++;
  // checkPassword rejects empty input without touching the network.
  await assert.rejects(B.checkPassword("")); n++;
  await assert.rejects(B.checkPassword(null)); n++;
  console.log(`verify_breach.js: ${n} assertions passed`);
}

main().catch((e) => { console.error("FAIL:", e.message); process.exit(1); });
