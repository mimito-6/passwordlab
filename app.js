/* PasswordLab — all computation is local. No network requests, no tracking. */
(function () {
  "use strict";

  var GUESSES_PER_SEC = 10000000000;
  var YEAR_SECONDS = 31557600;

  var COMMON = [
    "password", "123456", "123456789", "qwerty", "12345678", "111111",
    "12345", "123123", "abc123", "password1", "1234567", "qwerty123",
    "1q2w3e4r", "admin", "welcome", "monkey", "dragon", "letmein",
    "football", "iloveyou", "master", "sunshine", "princess", "shadow",
    "michael", "jennifer", "hunter", "baseball", "superman", "qazwsx",
    "trustno1", "jordan", "zxcvbnm", "password123", "passw0rd",
    "1234567890", "12345678910", "000000", "qwertyuiop", "1qaz2wsx",
    "654321", "jesus", "ninja", "mustang", "1234", "solo", "loveme",
    "charlie", "aa123456", "donald", "freedom"
  ];

  var KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "poiuytrewq", "lkjhgfdsa", "mnbvcxz"];

  var CLASS_NAMES = [
    ["lowercase letters", function (c) { return c >= "a" && c <= "z"; }, 26, "a–z"],
    ["uppercase letters", function (c) { return c >= "A" && c <= "Z"; }, 26, "A–Z"],
    ["digits", function (c) { return c >= "0" && c <= "9"; }, 10, "0–9"],
    ["symbols", function (c) {
      return !(c >= "a" && c <= "z") && !(c >= "A" && c <= "Z") && !(c >= "0" && c <= "9");
    }, 32, "!@#$…"]
  ];

  function charsetSize(pw) {
    var n = 0;
    for (var i = 0; i < CLASS_NAMES.length; i++) {
      var test = CLASS_NAMES[i][1], found = false;
      for (var j = 0; j < pw.length && !found; j++) if (test(pw[j])) found = true;
      if (found) n += CLASS_NAMES[i][2];
    }
    return n;
  }

  function hasClass(pw, idx) {
    var test = CLASS_NAMES[idx][1];
    for (var j = 0; j < pw.length; j++) if (test(pw[j])) return true;
    return false;
  }

  function findKeyboardWalk(pw) {
    var low = pw.toLowerCase();
    for (var r = 0; r < KEYBOARD_ROWS.length; r++) {
      var row = KEYBOARD_ROWS[r];
      for (var i = 0; i + 4 <= row.length; i++) {
        var seq = row.slice(i, i + 4);
        var rev = seq.split("").reverse().join("");
        if (low.indexOf(seq) !== -1 || low.indexOf(rev) !== -1) return seq;
      }
    }
    return null;
  }

  function smallestRepeatUnit(pw) {
    // Returns {unit, repeats} if the whole password is a repeated unit (unit shorter than pw)
    for (var u = 1; u <= Math.floor(pw.length / 2); u++) {
      if (pw.length % u !== 0) continue;
      var unit = pw.slice(0, u), ok = true;
      for (var k = u; k < pw.length; k += u) {
        if (pw.slice(k, k + u) !== unit) { ok = false; break; }
      }
      if (ok) return { unit: unit, repeats: pw.length / u };
    }
    return null;
  }

  function analyze(pw) {
    var warnings = [];
    var isCommon = COMMON.indexOf(pw.toLowerCase()) !== -1;
    var walk = findKeyboardWalk(pw);
    var rep = smallestRepeatUnit(pw);

    var entropy, displayEntropy, combos, seconds, instant;

    if (isCommon) {
      warnings.push({ cls: "", text: "This password is on common-password lists. Attackers try it within seconds — it is effectively crackable instantly, regardless of length." });
      instant = true;
      var cs = charsetSize(pw);
      entropy = pw.length * Math.log2(cs);
      displayEntropy = entropy;
      combos = Math.pow(2, entropy);
      seconds = 0;
    } else {
      instant = false;
      var baseLen = pw.length, baseCs = charsetSize(pw);
      if (rep) {
        warnings.push({ cls: "note", text: "Repeated pattern detected (" + rep.repeats + "× \"" + rep.unit + "\"). Entropy is computed on the unit, not the full length." });
        baseLen = rep.unit.length;
      }
      entropy = baseLen * Math.log2(baseCs);
      displayEntropy = entropy;
      if (walk) {
        // Keyboard-walk penalty: the walk counts as 20 bits (one of ~1M known patterns)
        var walkBits = Math.min(20, 4 * Math.log2(baseCs));
        var saved = 4 * Math.log2(baseCs) - walkBits;
        entropy = Math.max(0, entropy - saved);
        warnings.push({ cls: "", text: "Keyboard-walk pattern detected (\"" + walk + "…\"). Real attackers try keyboard patterns early — the estimate is reduced accordingly." });
        displayEntropy = entropy;
      }
      combos = Math.pow(2, entropy);
      seconds = combos / GUESSES_PER_SEC;
    }
    return { entropy: displayEntropy, combos: combos, seconds: seconds, instant: instant, warnings: warnings };
  }

  function formatTime(s) {
    if (s <= 0) return "instantly";
    if (s < 1e-6) return (s * 1e9).toFixed(1) + " nanoseconds";
    if (s < 1e-3) return (s * 1e6).toFixed(1) + " microseconds";
    if (s < 1) return (s * 1e3).toFixed(1) + " milliseconds";
    if (s < 60) return s.toFixed(1) + " seconds";
    if (s < 3600) return (s / 60).toFixed(1) + " minutes";
    if (s < 86400) return (s / 3600).toFixed(1) + " hours";
    if (s < YEAR_SECONDS) return (s / 86400).toFixed(1) + " days";
    var y = s / YEAR_SECONDS;
    if (y < 1000) return y.toLocaleString("en-US", { maximumFractionDigits: 1 }) + " years";
    if (y < 1e6) return Math.round(y).toLocaleString("en-US") + " years";
    return y.toExponential(2) + " years";
  }

  function fmtCombos(c) {
    if (!isFinite(c)) return "∞";
    if (c < 1e6) return Math.round(c).toLocaleString("en-US");
    return c.toExponential(2).replace("e+", "×10^");
  }

  function verdictFor(r) {
    if (r.instant) return ["Cracked instantly", "critical"];
    var s = r.seconds;
    if (s < 60) return ["Very weak", "critical"];
    if (s < 86400) return ["Weak", "weak"];
    if (s < YEAR_SECONDS) return ["Fair", "weak"];
    if (s < 100 * YEAR_SECONDS) return ["Strong", "strong"];
    return ["Very strong", "strong"];
  }

  var pw = document.getElementById("pw");
  var toggle = document.getElementById("toggle");
  var result = document.getElementById("result");
  var verdictEl = document.getElementById("verdict");
  var bignum = document.getElementById("bignum");
  var entropyEl = document.getElementById("entropy");
  var lengthEl = document.getElementById("length");
  var combosEl = document.getElementById("combos");
  var charsetEl = document.getElementById("charset");
  var warningsEl = document.getElementById("warnings");
  var copyBtn = document.getElementById("copy");
  var copyHint = document.getElementById("copyHint");
  var lastShareText = "";

  toggle.addEventListener("click", function () {
    var show = pw.type === "password";
    pw.type = show ? "text" : "password";
    toggle.textContent = show ? "Hide" : "Show";
    toggle.setAttribute("aria-pressed", show ? "true" : "false");
    toggle.setAttribute("aria-label", show ? "Hide password" : "Show password");
  });

  function render() {
    var v = pw.value;
    if (!v) { result.hidden = true; return; }
    result.hidden = false;
    var r = analyze(v);
    var vd = verdictFor(r);
    verdictEl.textContent = vd[0];
    verdictEl.className = "verdict " + vd[1];
    bignum.textContent = r.instant ? "instantly" : formatTime(r.seconds);
    entropyEl.textContent = r.entropy.toFixed(1) + " bits";
    lengthEl.textContent = v.length + " characters";
    combosEl.textContent = fmtCombos(r.combos);

    charsetEl.innerHTML = "";
    for (var i = 0; i < CLASS_NAMES.length; i++) {
      var chip = document.createElement("span");
      chip.className = "chip" + (hasClass(v, i) ? " on" : "");
      chip.textContent = (hasClass(v, i) ? "✓ " : "✕ ") + CLASS_NAMES[i][0] + " (" + CLASS_NAMES[i][3] + ")";
      charsetEl.appendChild(chip);
    }

    warningsEl.innerHTML = "";
    r.warnings.forEach(function (w) {
      var d = document.createElement("div");
      d.className = "warn " + w.cls;
      d.textContent = "⚠️ " + w.text;
      warningsEl.appendChild(d);
    });

    var timeStr = r.instant ? "instantly (it's on common-password lists)" : formatTime(r.seconds);
    lastShareText = "How long would YOUR password survive? Mine: " + r.entropy.toFixed(0) +
      " bits of entropy, ~" + timeStr + " to crack (offline attack, 10B guesses/sec). " +
      "Test yours (nothing leaves your device): https://password.mimito6.uk/";
  }

  pw.addEventListener("input", render);

  copyBtn.addEventListener("click", function () {
    function done() {
      copyHint.hidden = false;
      setTimeout(function () { copyHint.hidden = true; }, 4000);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(lastShareText).then(done, function () { fallback(); });
    } else { fallback(); }
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = lastShareText;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch (e) {}
      document.body.removeChild(ta);
      done();
    }
  });
})();
