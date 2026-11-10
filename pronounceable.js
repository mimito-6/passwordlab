/* PasswordLab Pronounceable Password Generator — all computation is local.
   No network requests. A pronounceable password is built from random syllables
   (onset + vowel nucleus + optional coda) so it reads like a made-up word and
   is far easier to remember than a random string of the same strength — at the
   cost of fewer bits per character. The trade is honest and quantified below.

   Math: a syllable is a uniform pick of onset x nucleus x coda.
   - onsets: 46 (18 single consonants + 28 clusters: bl br ch cl cr dr fl fr gl
     gr pl pr sh sl sm sn sp st str sw th tr tw wh qu spr scr spl)
   - nuclei: 24 (a e i o u + 19 digraphs: ai au ea ee ei eu ia ie io oa oe oi
     oo ou ue ui ay ey oy)
   - codas: 17 (none + 16 single consonants: b c d f g k l m n p r s t v x z)
   Syllable space = 46 x 24 x 17 = 18,768; log2 = 14.196 bits per syllable.
   Entropy = syllables x 14.196 + log2(10) if a digit is appended
             + log2(12) if a symbol is appended (12 symbols: ! @ # $ % ^ & * ? + - =).
   Capitalizing the first letter adds 0 bits: the position is fixed, so an
   attacker who knows the rule gains nothing — the page says so instead of
   pretending otherwise.
   Offline crack time = combinations / 10 billion guesses per second — the same
   documented model as the rest of PasswordLab. It is an upper bound, not a
   promise: a leaked password is compromised the moment it leaks, and a weak
   master password protecting a vault is worth no bits at all. */
(function (root) {
  "use strict";

  var GUESSES_PER_SEC = 10000000000;

  var ONSETS = ["b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p",
    "r", "s", "t", "v", "w", "z",
    "bl", "br", "ch", "cl", "cr", "dr", "fl", "fr", "gl", "gr", "pl", "pr",
    "sh", "sl", "sm", "sn", "sp", "st", "str", "sw", "th", "tr", "tw", "wh",
    "qu", "spr", "scr", "spl"];
  var NUCLEI = ["a", "e", "i", "o", "u",
    "ai", "au", "ea", "ee", "ei", "eu", "ia", "ie", "io", "oa", "oe", "oi",
    "oo", "ou", "ue", "ui", "ay", "ey", "oy"];
  var CODAS = ["", "b", "c", "d", "f", "g", "k", "l", "m", "n", "p", "r",
    "s", "t", "v", "x", "z"];
  var SYMBOLS = "!@#$%^&*?+-=";

  var SYLLABLE_SPACE = ONSETS.length * NUCLEI.length * CODAS.length; // 18,768
  var BITS_PER_SYLLABLE = Math.log(SYLLABLE_SPACE) / Math.log(2); // 14.196

  function validSyllables(n) {
    return typeof n === "number" && isFinite(n) && Math.floor(n) === n && n >= 2 && n <= 6;
  }

  function entropyBits(syllables, opts) {
    if (!validSyllables(syllables)) return null;
    opts = opts || {};
    var bits = syllables * BITS_PER_SYLLABLE;
    if (opts.digit) bits += Math.log(10) / Math.log(2);
    if (opts.symbol) bits += Math.log(SYMBOLS.length) / Math.log(2);
    return bits; // capitalize adds 0 bits: fixed position, attacker knows the rule
  }

  function crackSeconds(syllables, opts) {
    var bits = entropyBits(syllables, opts);
    if (bits === null) return null;
    return Math.pow(2, bits) / GUESSES_PER_SEC;
  }

  function formatCombinations(syllables, opts) {
    var bits = entropyBits(syllables, opts);
    if (bits === null) return "–";
    var log10 = bits * Math.log10(2);
    if (log10 < 6) return Math.pow(2, bits).toLocaleString("en-US");
    var exp = Math.floor(log10);
    var mantissa = Math.pow(10, log10 - exp);
    return mantissa.toFixed(1) + " × 10^" + exp;
  }

  function formatDuration(seconds) {
    if (seconds === null || !isFinite(seconds)) return "effectively forever";
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

  function makeSyllable(rng) {
    return ONSETS[rng(ONSETS.length)] + NUCLEI[rng(NUCLEI.length)] + CODAS[rng(CODAS.length)];
  }

  function generate(syllables, opts, rng) {
    if (!validSyllables(syllables)) return null;
    opts = opts || {};
    rng = rng || defaultRng;
    var parts = [];
    for (var i = 0; i < syllables; i++) parts.push(makeSyllable(rng));
    var out = parts.join("");
    if (opts.capitalize) out = out.charAt(0).toUpperCase() + out.slice(1);
    if (opts.digit) out += String(rng(10));
    if (opts.symbol) out += SYMBOLS.charAt(rng(SYMBOLS.length));
    return out;
  }

  // Verdicts judge bits against offline cracking, the threat model for a
  // password an attacker can test without limit: under 40 bits falls in
  // minutes, 40-60 bits buys months at best, 60-80 bits is strong, and 80+
  // bits is very strong. The default 4 syllables (56.8 bits) is only "fair":
  // memorable, but pick 5 syllables if the password must survive offline attack.
  function verdict(bits) {
    if (bits === null) return ["invalid settings", "weak"];
    if (bits < 40) return ["too short — guessable in minutes", "weak"];
    if (bits < 60) return ["memorable, but offline-weak", "fair"];
    if (bits < 80) return ["strong", "strong"];
    return ["very strong", "strong"];
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("genBtn")) return;
    var syl = $("sylRange"), sylLabel = $("sylLabel");
    function syncLabel() { sylLabel.textContent = syl.value; }
    syl.addEventListener("input", syncLabel); syncLabel();

    function opts() {
      return {
        capitalize: $("capCheck").checked,
        digit: $("digitCheck").checked,
        symbol: $("symbolCheck").checked
      };
    }

    function run() {
      var n = parseInt(syl.value, 10);
      var o = opts();
      var pw = generate(n, o);
      var bits = entropyBits(n, o);
      var v = verdict(bits);
      $("output").textContent = pw;
      $("output").setAttribute("data-hidden", "false");
      $("showBtn").textContent = "Hide";
      $("result").hidden = false;
      $("entropy").textContent = bits.toFixed(1) + " bits";
      $("combos").textContent = formatCombinations(n, o);
      $("length").textContent = pw.length + " characters";
      $("bignum").textContent = formatDuration(crackSeconds(n, o));
      var ve = $("verdict");
      ve.textContent = v[0].toUpperCase();
      ve.className = "verdict " + v[1];
    }
    $("genBtn").addEventListener("click", run);
    syl.addEventListener("input", run);
    ["capCheck", "digitCheck", "symbolCheck"].forEach(function (id) {
      $(id).addEventListener("change", run);
    });
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
    ONSETS: ONSETS, NUCLEI: NUCLEI, CODAS: CODAS, SYMBOLS: SYMBOLS,
    SYLLABLE_SPACE: SYLLABLE_SPACE, BITS_PER_SYLLABLE: BITS_PER_SYLLABLE,
    entropyBits: entropyBits, crackSeconds: crackSeconds,
    formatCombinations: formatCombinations, formatDuration: formatDuration,
    generate: generate, verdict: verdict
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PronounceableGen = api;
})(typeof self !== "undefined" ? self : this);
