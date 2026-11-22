/* PasswordLab Backup Codes Generator — all computation is local. No network requests, no tracking.
   Backup codes are single-use recovery codes (the "print these and keep them safe" list
   a service gives you when you turn on two-factor authentication). They are verified
   server-side, one code at a time, so the honest threat model is different from a password:
   - An attacker cannot test codes offline against a leaked hash; they must ask the server,
     which locks the account after a few wrong tries. So the number that matters is the
     chance of guessing one code in 10 tries: 10 / combinations.
   - The real risk is the list itself leaking: every code on it works, so a stolen list is
     a full compromise until you revoke and regenerate. Store the list offline (printed,
     in a password manager), never in a plain file or a screenshot.
   - Entropy is still reported per code, because a code is a random secret: bits = log2(pool^length).
     8 digits = 26.6 bits (100,000,000 combinations); 8 alphanumeric = 47.6 bits
     (62^8 = 218,340,105,584,896); 16 hex = 64.0 bits (16^16 = 2^64).
   Generation uses crypto.getRandomValues with rejection sampling (no modulo bias). */
(function (root) {
  "use strict";

  var LOCKOUT_TRIES = 10;
  var MIN_COUNT = 1;
  var MAX_COUNT = 20;

  var FORMATS = {
    digits: { label: "8 digits", length: 8, charset: "0123456789", group: 4, sep: " " },
    alnum: { label: "8 letters + digits", length: 8, charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", group: 4, sep: "-" },
    hex: { label: "16 hex characters", length: 16, charset: "0123456789abcdef", group: 4, sep: "-" }
  };

  function formatDef(format) {
    return Object.prototype.hasOwnProperty.call(FORMATS, format) ? FORMATS[format] : null;
  }

  function combinations(format) {
    var def = formatDef(format);
    if (!def) return null;
    return Math.pow(def.charset.length, def.length);
  }

  function entropyBits(format) {
    var combos = combinations(format);
    if (combos === null) return null;
    return Math.log(combos) / Math.log(2);
  }

  function formatCode(raw, format) {
    var def = formatDef(format);
    if (!def) return null;
    if (typeof raw !== "string" || raw.length !== def.length) return null;
    var parts = [];
    for (var i = 0; i < raw.length; i += def.group) parts.push(raw.slice(i, i + def.group));
    return parts.join(def.sep);
  }

  // rng: function returning a uniform integer in [0, max). Defaults to crypto.getRandomValues
  // with rejection sampling (no modulo bias).
  function defaultRng(max) {
    var buf = new Uint16Array(1);
    var limit = 65536 - (65536 % max);
    var v;
    do {
      (root.crypto || window.crypto).getRandomValues(buf);
      v = buf[0];
    } while (v >= limit);
    return v % max;
  }

  function generateCode(format, rng) {
    var def = formatDef(format);
    if (!def) return null;
    rng = rng || defaultRng;
    var raw = "";
    for (var i = 0; i < def.length; i++) raw += def.charset[rng(def.charset.length)];
    return formatCode(raw, format);
  }

  function generateSet(count, format, rng) {
    if (typeof count !== "number" || count < MIN_COUNT || count > MAX_COUNT || count % 1 !== 0) return null;
    if (!formatDef(format)) return null;
    var out = [];
    for (var i = 0; i < count; i++) out.push(generateCode(format, rng));
    return out;
  }

  // Verdicts judge the code as a server-checked, lockout-protected secret — not as a
  // password hash target. Even the weakest format is safe against online guessing
  // (10 tries in 100 million); the scale instead reflects how much margin the format
  // has if a service's lockout is weak or absent.
  function verdict(format) {
    if (format === "digits") return ["weak alone — needs a lockout", "weak"];
    if (format === "alnum") return ["fair — fine with a lockout", "fair"];
    if (format === "hex") return ["strong for a backup code", "strong"];
    return null;
  }

  function formatCombinations(combos) {
    if (combos < 1000000) return combos.toLocaleString("en-US");
    return combos.toExponential(1).replace("e+", " × 10^");
  }

  function formatChance(combos) {
    var p = LOCKOUT_TRIES / combos * 100;
    if (p >= 0.01) return p.toFixed(3).replace(/0+$/, "").replace(/\.$/, "") + "%";
    return p.toExponential(1) + "%";
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("genBtn")) return;
    var countRange = $("bcCountRange"), countLabel = $("bcCountLabel");
    var codes = [];
    var hidden = false;

    function currentFormat() {
      var radios = document.getElementsByName("bcFormat");
      for (var i = 0; i < radios.length; i++) if (radios[i].checked) return radios[i].value;
      return "digits";
    }

    function renderStats(format) {
      var combos = combinations(format);
      var bits = entropyBits(format);
      var v = verdict(format);
      $("entropy").textContent = bits.toFixed(1) + " bits per code";
      $("combos").textContent = formatCombinations(combos) + " per code";
      $("avgGuesses").textContent = formatCombinations(combos / 2) + " guesses on average";
      $("lockoutChance").textContent = formatChance(combos) + " (10 tries)";
      var ve = $("verdict");
      ve.textContent = v[0].toUpperCase();
      ve.className = "verdict " + v[1];
    }

    function renderList() {
      var list = $("codeList");
      list.innerHTML = "";
      codes.forEach(function (code, i) {
        var li = document.createElement("li");
        li.className = "code-row";
        var span = document.createElement("code");
        span.className = "code-text";
        span.textContent = hidden ? "•".repeat(code.length) : code;
        span.setAttribute("data-code", code);
        var copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "mini-btn";
        copyBtn.textContent = "Copy";
        copyBtn.addEventListener("click", function () {
          navigator.clipboard.writeText(code).then(function () {
            copyBtn.textContent = "Copied";
            setTimeout(function () { copyBtn.textContent = "Copy"; }, 1500);
          });
        });
        var regenBtn = document.createElement("button");
        regenBtn.type = "button";
        regenBtn.className = "mini-btn";
        regenBtn.textContent = "↻ New";
        regenBtn.setAttribute("aria-label", "Regenerate code " + (i + 1));
        regenBtn.addEventListener("click", function () {
          codes[i] = generateCode(currentFormat());
          renderList();
        });
        li.appendChild(span);
        li.appendChild(copyBtn);
        li.appendChild(regenBtn);
        list.appendChild(li);
      });
    }

    function run() {
      var count = parseInt(countRange.value, 10);
      var format = currentFormat();
      codes = generateSet(count, format);
      hidden = false;
      $("showBtn").textContent = "Hide";
      $("result").hidden = false;
      renderStats(format);
      renderList();
    }

    function syncLabel() { countLabel.textContent = countRange.value; }
    countRange.addEventListener("input", function () { syncLabel(); run(); });
    syncLabel();
    var radios = document.getElementsByName("bcFormat");
    for (var i = 0; i < radios.length; i++) radios[i].addEventListener("change", run);
    $("genBtn").addEventListener("click", run);
    $("showBtn").addEventListener("click", function () {
      hidden = !hidden;
      $("showBtn").textContent = hidden ? "Show" : "Hide";
      renderList();
    });
    $("copyAllBtn").addEventListener("click", function () {
      navigator.clipboard.writeText(codes.join("\n")).then(function () {
        $("copyHint").hidden = false;
        setTimeout(function () { $("copyHint").hidden = true; }, 2500);
      });
    });
    $("downloadBtn").addEventListener("click", function () {
      var blob = new Blob([codes.join("\n") + "\n"], { type: "text/plain" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "passwordlab-backup-codes.txt";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    });
    run();
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }

  var api = {
    combinations: combinations, entropyBits: entropyBits,
    formatCode: formatCode, generateCode: generateCode, generateSet: generateSet,
    verdict: verdict, formatCombinations: formatCombinations, formatChance: formatChance,
    FORMATS: FORMATS, MIN_COUNT: MIN_COUNT, MAX_COUNT: MAX_COUNT
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.BackupCodes = api;
})(typeof self !== "undefined" ? self : this);
