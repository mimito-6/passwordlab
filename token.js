/* PasswordLab Random Token Generator — all computation is local. No network requests.
   A token is a random string for machine use: API keys, session tokens, reset links.
   Unlike a human password it is never meant to be memorized, so it can be long and
   drawn from a restricted, URL-safe alphabet.
   Math: each character is a uniform pick from its format's alphabet.
   - hex: 16 symbols, 4.000 bits per character.
   - base64url: 64 symbols (A-Z, a-z, 0-9, -, _), 6.000 bits per character.
   - alphanumeric: 62 symbols, log2(62) = 5.954 bits per character.
   Entropy = length x bits per character. Combinations = pool ^ length.
   Offline crack time = combinations / 10 billion guesses per second — the same
   documented model as the rest of PasswordLab. It is an upper bound, not a promise:
   a leaked token is compromised the moment it leaks, regardless of entropy, which
   is why the page says to rotate leaked tokens immediately instead of trusting bits. */
(function (root) {
  "use strict";

  var GUESSES_PER_SEC = 10000000000;

  var FORMATS = {
    hex: { pool: 16, charset: "0123456789abcdef", label: "Hex (0-9, a-f)" },
    base64url: { pool: 64, charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", label: "Base64url (A-Z, a-z, 0-9, -, _)" },
    alphanumeric: { pool: 62, charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", label: "Alphanumeric (A-Z, a-z, 0-9)" }
  };

  function entropyBits(format, length) {
    return length * (Math.log(FORMATS[format].pool) / Math.log(2));
  }

  function crackSeconds(format, length) {
    return Math.pow(FORMATS[format].pool, length) / GUESSES_PER_SEC;
  }

  function formatCombinations(format, length) {
    var bits = entropyBits(format, length);
    var log10 = bits * Math.log10(2);
    if (log10 < 6) return Math.pow(FORMATS[format].pool, length).toLocaleString("en-US");
    var exp = Math.floor(log10);
    var mantissa = Math.pow(10, log10 - exp);
    return mantissa.toFixed(1) + " × 10^" + exp;
  }

  function formatDuration(seconds) {
    if (!isFinite(seconds)) return "effectively forever";
    if (seconds < 1) return "instantly";
    var years = seconds / 31557600;
    if (years >= 10000) {
      var exp = Math.floor(Math.log10(years));
      var mantissa = years / Math.pow(10, exp);
      return mantissa.toFixed(1) + " × 10^" + exp + " years";
    }
    var units = [
      [31557600, "year"], [86400, "day"], [3600, "hour"], [60, "minute"], [1, "second"]
    ];
    for (var i = 0; i < units.length; i++) {
      if (seconds >= units[i][0] * 0.95) {
        var v = seconds / units[i][0];
        var shown = v >= 100 ? Math.round(v).toString() : v.toFixed(1);
        return shown + " " + units[i][1] + (shown === "1.0" || shown === "1" ? "" : "s");
      }
    }
    return seconds.toFixed(2) + " seconds";
  }

  // rng: function returning a uniform integer in [0, max). Defaults to
  // crypto.getRandomValues with rejection sampling (no modulo bias).
  function defaultRng(max) {
    var buf = new Uint16Array(1);
    var limit = 65536 - (65536 % max);
    var c = root.crypto;
    if (!c && typeof window !== "undefined") c = window.crypto;
    if (!c && typeof require === "function") {
      try { c = require("crypto").webcrypto; } catch (e) { /* browser: no require */ }
    }
    var v;
    do {
      c.getRandomValues(buf);
      v = buf[0];
    } while (v >= limit);
    return v % max;
  }

  function generate(format, length, rng) {
    rng = rng || defaultRng;
    var charset = FORMATS[format].charset;
    var out = "";
    for (var i = 0; i < length; i++) out += charset.charAt(rng(charset.length));
    return out;
  }

  // Token verdicts judge bits against machine-secret practice: 128 bits is the
  // standard target (e.g. a 32-character hex token). Below 64 bits a token is
  // genuinely guessable; 64-127 bits is usable but below the modern bar.
  function verdict(bits) {
    if (bits < 64) return ["too short for a secret", "weak"];
    if (bits < 128) return ["usable, below the 128-bit bar", "fair"];
    return ["128+ bits — standard strength", "strong"];
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("genBtn")) return;
    var len = $("tokLenRange"), lenLabel = $("tokLenLabel");
    function syncLabel() { lenLabel.textContent = len.value; }
    len.addEventListener("input", syncLabel); syncLabel();

    function run() {
      var format = document.querySelector('input[name="tokFormat"]:checked').value;
      var length = parseInt(len.value, 10);
      var token = generate(format, length);
      var bits = entropyBits(format, length);
      var v = verdict(bits);
      $("output").textContent = token;
      $("output").setAttribute("data-hidden", "false");
      $("showBtn").textContent = "Hide";
      $("result").hidden = false;
      $("entropy").textContent = bits.toFixed(1) + " bits";
      $("combos").textContent = formatCombinations(format, length);
      $("bignum").textContent = formatDuration(crackSeconds(format, length));
      var ve = $("verdict");
      ve.textContent = v[0].toUpperCase();
      ve.className = "verdict " + v[1];
    }
    $("genBtn").addEventListener("click", run);
    var radios = document.querySelectorAll('input[name="tokFormat"]');
    for (var i = 0; i < radios.length; i++) radios[i].addEventListener("change", run);
    len.addEventListener("input", run);
    $("showBtn").addEventListener("click", function () {
      var out = $("output");
      var hidden = out.getAttribute("data-hidden") === "true";
      if (hidden) { out.textContent = out.getAttribute("data-token"); out.setAttribute("data-hidden", "false"); $("showBtn").textContent = "Hide"; }
      else { out.setAttribute("data-token", out.textContent); out.textContent = "•".repeat(out.textContent.length); out.setAttribute("data-hidden", "true"); $("showBtn").textContent = "Show"; }
    });
    $("copyBtn").addEventListener("click", function () {
      var out = $("output");
      var text = out.getAttribute("data-hidden") === "true" ? out.getAttribute("data-token") : out.textContent;
      navigator.clipboard.writeText(text).then(function () {
        $("copyHint").hidden = false;
        setTimeout(function () { $("copyHint").hidden = true; }, 2500);
      });
    });
    run();
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }

  var api = {
    FORMATS: FORMATS, entropyBits: entropyBits, crackSeconds: crackSeconds,
    formatCombinations: formatCombinations, formatDuration: formatDuration,
    generate: generate, verdict: verdict
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.TokenGen = api;
})(typeof self !== "undefined" ? self : this);
