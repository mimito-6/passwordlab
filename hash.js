/* PasswordLab Hash Generator — all computation is local. No network requests.
   A cryptographic hash turns any input into a fixed-length fingerprint: SHA-256
   always yields 64 hex characters (256 bits), SHA-384 yields 96 (384 bits),
   SHA-512 yields 128 (512 bits). The same input always gives the same hash;
   changing one character changes about half the output bits (avalanche).
   The browser's WebCrypto (crypto.subtle.digest) does the work; Node tests use
   require("crypto").webcrypto.subtle, the same standard API.
   Honesty notes, stated on the page too: a hash is one-way, not encryption —
   it cannot be "decoded" back to the input. It is also not a password store:
   unsalted fast hashes of passwords fall to dictionary attacks, which is why
   password storage needs a slow, salted KDF (bcrypt/argon2), not a bare hash.
   MD5 and SHA-1 are deliberately not offered: both are broken for collision
   resistance, and offering them would invite misuse. */
(function (root) {
  "use strict";

  var ALGOS = {
    "SHA-256": { bits: 256, hexChars: 64, label: "SHA-256" },
    "SHA-384": { bits: 384, hexChars: 96, label: "SHA-384" },
    "SHA-512": { bits: 512, hexChars: 128, label: "SHA-512" }
  };

  function getSubtle() {
    var c = null;
    if (root.crypto && root.crypto.subtle) c = root.crypto;
    else if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) c = window.crypto;
    else if (typeof require === "function") {
      try { c = require("crypto").webcrypto; } catch (e) { /* browser: no require */ }
    }
    return c ? c.subtle : null;
  }

  function bytesToHex(buf) {
    var bytes = new Uint8Array(buf);
    var out = "";
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      out += h.length === 1 ? "0" + h : h;
    }
    return out;
  }

  function encodeUtf8(text) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text).buffer;
    return Buffer.from(text, "utf8").buffer;
  }

  // algo: "SHA-256" | "SHA-384" | "SHA-512". Returns a Promise<string> (hex).
  function digestHex(algo, text) {
    if (!ALGOS[algo]) return Promise.reject(new Error("unknown algorithm: " + algo));
    var subtle = getSubtle();
    if (!subtle) return Promise.reject(new Error("WebCrypto is not available in this environment"));
    return subtle.digest(algo, encodeUtf8(text)).then(bytesToHex);
  }

  // Hash an ArrayBuffer (e.g. a file read with arrayBuffer()). Returns Promise<string>.
  function digestBuffer(algo, buffer) {
    if (!ALGOS[algo]) return Promise.reject(new Error("unknown algorithm: " + algo));
    var subtle = getSubtle();
    if (!subtle) return Promise.reject(new Error("WebCrypto is not available in this environment"));
    return subtle.digest(algo, buffer).then(bytesToHex);
  }

  function hexLength(algo) { return ALGOS[algo] ? ALGOS[algo].hexChars : null; }
  function bits(algo) { return ALGOS[algo] ? ALGOS[algo].bits : null; }

  // Normalize a pasted hash for comparison: strip whitespace, lowercase.
  // Returns the cleaned string, or null if it is not hex at all.
  function normalizeHash(s) {
    if (typeof s !== "string") return null;
    var cleaned = s.replace(/\s+/g, "").toLowerCase();
    if (cleaned.length === 0) return null;
    if (!/^[0-9a-f]+$/.test(cleaned)) return null;
    return cleaned;
  }

  // Compare a computed hash with a pasted one (case- and whitespace-insensitive).
  // Returns "match", "mismatch", or "invalid" (pasted value is not a hex hash).
  function compareHashes(computed, pasted) {
    var a = normalizeHash(computed);
    var b = normalizeHash(pasted);
    if (!a || !b) return "invalid";
    return a === b ? "match" : "mismatch";
  }

  function utf8ByteLength(text) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text).length;
    return Buffer.byteLength(text, "utf8");
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("hashInput")) return;

    var lastHash = "";

    function currentAlgo() {
      var r = document.querySelector('input[name="hashAlgo"]:checked');
      return r ? r.value : "SHA-256";
    }

    function renderCompare() {
      var v = $("compareVerdict");
      var pasted = $("compareInput").value;
      if (!lastHash) { v.textContent = "Hash something first, then paste a hash to compare."; v.className = "verdict"; return; }
      if (!pasted.trim()) { v.textContent = "Paste a hash above to check it against the computed hash."; v.className = "verdict"; return; }
      var res = compareHashes(lastHash, pasted);
      if (res === "match") { v.textContent = "MATCH — the pasted hash is identical to the computed hash."; v.className = "verdict strong"; }
      else if (res === "mismatch") { v.textContent = "NO MATCH — at least one character differs. Check the algorithm and the input (even one changed character changes the hash)."; v.className = "verdict weak"; }
      else { v.textContent = "That does not look like a hex hash — it should be only 0-9 and a-f."; v.className = "verdict weak"; }
    }

    function run() {
      var algo = currentAlgo();
      var text = $("hashInput").value;
      $("inputBytes").textContent = utf8ByteLength(text).toLocaleString("en-US") + " bytes (UTF-8)";
      $("hashBits").textContent = ALGOS[algo].bits + " bits · " + ALGOS[algo].hexChars + " hex characters";
      digestHex(algo, text).then(function (hex) {
        lastHash = hex;
        $("hashOutput").textContent = hex;
        $("result").hidden = false;
        renderCompare();
      }).catch(function (e) {
        $("hashOutput").textContent = "Error: " + e.message;
        $("result").hidden = false;
      });
    }

    $("hashInput").addEventListener("input", run);
    var radios = document.querySelectorAll('input[name="hashAlgo"]');
    for (var i = 0; i < radios.length; i++) radios[i].addEventListener("change", run);
    $("compareInput").addEventListener("input", renderCompare);
    $("copyHashBtn").addEventListener("click", function () {
      if (!lastHash) return;
      navigator.clipboard.writeText(lastHash).then(function () {
        $("copyHint").hidden = false;
        setTimeout(function () { $("copyHint").hidden = true; }, 2500);
      });
    });
    $("hashFile").addEventListener("change", function () {
      var file = $("hashFile").files && $("hashFile").files[0];
      if (!file) return;
      $("fileStatus").textContent = "Hashing " + file.name + " (" + file.size.toLocaleString("en-US") + " bytes)…";
      file.arrayBuffer().then(function (buf) {
        return digestBuffer(currentAlgo(), buf);
      }).then(function (hex) {
        lastHash = hex;
        $("hashOutput").textContent = hex;
        $("result").hidden = false;
        $("fileStatus").textContent = "Hashed " + file.name + " with " + currentAlgo() + " — the file never left your device.";
        renderCompare();
      }).catch(function (e) {
        $("fileStatus").textContent = "Error: " + e.message;
      });
    });
    run();
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }

  var api = {
    ALGOS: ALGOS, digestHex: digestHex, digestBuffer: digestBuffer,
    hexLength: hexLength, bits: bits, normalizeHash: normalizeHash,
    compareHashes: compareHashes, utf8ByteLength: utf8ByteLength
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.HashGen = api;
})(typeof self !== "undefined" ? self : this);
