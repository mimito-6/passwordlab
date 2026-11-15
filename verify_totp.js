/* Verify totp.js against RFC 6238 Appendix B test vectors, computed independently
   with Python's hmac module (/tmp/totp_mirror.py). Run: node verify_totp.js
   Expected anchors: SHA-1 at T=59 -> 94287082, at T=1111111109 -> 07081804. */
"use strict";
const T = require("./totp.js");

const SECRETS = {
  "SHA-1": Buffer.from("12345678901234567890", "ascii"),
  "SHA-256": Buffer.from("12345678901234567890123456789012", "ascii"),
  "SHA-512": Buffer.from("1234567890123456789012345678901234567890123456789012345678901234", "ascii"),
};
const TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];
// RFC 6238 Appendix B, 8-digit codes (verified by independent Python mirror).
const EXPECTED = {
  "SHA-1": ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
  "SHA-256": ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
  "SHA-512": ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"],
};
const EXPECTED_6 = ["287082", "081804", "050471", "005924", "279037", "353130"]; // SHA-1, 6-digit

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  if (!ok) { failures++; console.log("FAIL " + name + ": got " + actual + ", want " + expected); }
  else console.log("ok   " + name + " = " + actual);
}

(async function main() {
  // 1. RFC 6238 vectors, all three algorithms, 8 digits.
  for (const algo of ["SHA-1", "SHA-256", "SHA-512"]) {
    for (let i = 0; i < TIMES.length; i++) {
      const code = await T.totpAt(new Uint8Array(SECRETS[algo]), TIMES[i], 8, algo, 30);
      check("RFC " + algo + " t=" + TIMES[i], code, EXPECTED[algo][i]);
    }
  }
  // 2. 6-digit codes are the last 6 digits of the 8-digit code (same truncation).
  for (let i = 0; i < TIMES.length; i++) {
    const code = await T.totpAt(new Uint8Array(SECRETS["SHA-1"]), TIMES[i], 6, "SHA-1", 30);
    check("RFC SHA-1 6-digit t=" + TIMES[i], code, EXPECTED_6[i]);
  }
  // 3. Counter arithmetic.
  check("counter t=59", String(T.counterForTime(59, 30)), "1");
  check("counter t=30", String(T.counterForTime(30, 30)), "1");
  check("counter t=29", String(T.counterForTime(29, 30)), "0");
  check("counter t=1111111109", String(T.counterForTime(1111111109, 30)), "37037036");
  check("counter t=20000000000 p60", String(T.counterForTime(20000000000, 60)), "333333333");
  // 4. secondsRemaining.
  check("remaining t=59 p30", String(T.secondsRemaining(59, 30)), "1");
  check("remaining t=45 p30", String(T.secondsRemaining(45, 30)), "15");
  check("remaining t=60 p30", String(T.secondsRemaining(60, 30)), "30");
  // 5. Base32 decode anchors.
  const b1 = T.base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  check("b32 RFC secret", Buffer.from(b1).toString("ascii"), "12345678901234567890");
  const b2 = T.base32Decode("JBSWY3DPEHPK3PXP");
  check("b32 Hello anchor", Buffer.from(b2).toString("latin1"), "Hello!\xde\xad\xbe\xef");
  const b3 = T.base32Decode("gezdgnbvgy3tqojq gezdgnbvgy3tqojq");
  check("b32 lowercase+spaces", Buffer.from(b3).toString("ascii"), "12345678901234567890");
  check("b32 invalid char", String(T.base32Decode("JBSW!3DP")), "null");
  check("b32 digit 1 invalid", String(T.base32Decode("JBSWY3D1")), "null");
  check("b32 empty", String(T.base32Decode("")), "null");
  check("b32 malformed leftover", String(T.base32Decode("A")), "null");
  // 6. otpauth URI exact string.
  check("otpauth uri",
    T.otpauthUri("alice@example.com", "Example", "JBSWY3DPEHPK3PXP", "SHA-1", 6, 30),
    "otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30");
  check("otpauth uri no issuer",
    T.otpauthUri("bob", "", "JBSWY3DPEHPK3PXP", "SHA-256", 8, 60),
    "otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP&issuer=&algorithm=SHA256&digits=8&period=60");
  // 7. Deterministic mock RNG: first 16 base32 chars in order.
  let n = 0;
  const mockRng = function () { return (n++) % 32; };
  check("generateSecret mock", T.generateSecret(16, mockRng), "ABCDEFGHIJKLMNOP");
  check("generateSecret length", String(T.generateSecret(16, mockRng).length), "16");
  // 8. Invalid inputs return null, not a code.
  check("totpAt empty key", String(await T.totpAt(new Uint8Array(0), 59, 6, "SHA-1", 30)), "null");
  check("totpAt bad digits", String(await T.totpAt(new Uint8Array(SECRETS["SHA-1"]), 59, 7, "SHA-1", 30)), "null");

  console.log(failures === 0 ? "ALL PASS" : failures + " FAILURES");
  process.exit(failures === 0 ? 0 : 1);
})().catch(function (e) { console.error("ERROR", e); process.exit(1); });
