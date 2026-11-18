// Verify hash.js against NIST/FIPS 180-4 test vectors (ground truth computed
// independently with Python hashlib before this file was written).
const assert = require("assert");
const H = require("./hash.js");

const VECTORS = [
  ["SHA-256", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
  ["SHA-256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
  ["SHA-256", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"],
  ["SHA-256", "abd", "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9"],
  ["SHA-384", "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"],
  ["SHA-384", "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"],
  ["SHA-384", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
   "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"],
  ["SHA-512", "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"],
  ["SHA-512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"],
  ["SHA-512", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
   "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"],
];

async function main() {
  let n = 0;
  for (const [algo, input, expected] of VECTORS) {
    const got = await H.digestHex(algo, input);
    assert.strictEqual(got, expected, `${algo}(${JSON.stringify(input)})`);
    n++;
  }
  // digestBuffer path (file hashing) must agree with digestHex on the same bytes.
  const abcBuf = Buffer.from("abc", "utf8");
  const buf = abcBuf.buffer.slice(abcBuf.byteOffset, abcBuf.byteOffset + 3);
  assert.strictEqual(await H.digestBuffer("SHA-256", buf),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "digestBuffer SHA-256('abc')");
  n++;
  // Metadata.
  assert.strictEqual(H.hexLength("SHA-256"), 64); n++;
  assert.strictEqual(H.hexLength("SHA-384"), 96); n++;
  assert.strictEqual(H.hexLength("SHA-512"), 128); n++;
  assert.strictEqual(H.bits("SHA-256"), 256); n++;
  assert.strictEqual(H.bits("SHA-512"), 512); n++;
  assert.strictEqual(H.hexLength("MD5"), null); n++;
  // UTF-8 byte length: "café" is 5 bytes, not 4 characters.
  assert.strictEqual(H.utf8ByteLength("café"), 5); n++;
  assert.strictEqual(H.utf8ByteLength("abc"), 3); n++;
  // Compare logic.
  const abc256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  assert.strictEqual(H.compareHashes(abc256, abc256.toUpperCase()), "match"); n++;
  assert.strictEqual(H.compareHashes(abc256, " " + abc256 + "\n"), "match"); n++;
  assert.strictEqual(H.compareHashes(abc256, abc256.slice(0, -1) + "e"), "mismatch"); n++;
  assert.strictEqual(H.compareHashes(abc256, "not a hash!"), "invalid"); n++;
  assert.strictEqual(H.compareHashes(abc256, ""), "invalid"); n++;
  assert.strictEqual(H.normalizeHash(" BA78 16BF "), "ba7816bf"); n++;
  assert.strictEqual(H.normalizeHash("zz"), null); n++;
  // Unknown algorithm must reject, not silently hash with a default.
  await assert.rejects(H.digestHex("MD5", "abc")); n++;
  console.log(`verify_hash.js: ${n} assertions passed`);
}

main().catch((e) => { console.error("FAIL:", e.message); process.exit(1); });
