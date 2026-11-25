/* PasswordLab Breach Checker — checks a password against the Have I Been Pwned
   (HIBP) Pwned Passwords corpus using k-anonymity, so the password itself never
   leaves the device.
   Protocol (Troy Hunt's design): SHA-1(password) is computed locally; only the
   first 5 hex characters (the "prefix", 20 bits) are sent to
   https://api.pwnedpasswords.com/range/<prefix>. The server returns every hash
   suffix sharing that prefix (typically ~2,000 lines, measured 1,977 for prefix
   5BAA6 and 2,509 for 00000 on 2026-11-25); the match against the remaining
   35 characters happens locally. The server therefore never sees the full hash,
   let alone the password, and cannot tell which of the ~2,000 candidates was
   checked. The request also sends "Add-Padding: true" so responses are padded
   to a uniform size.
   Honesty notes, stated on the page too: SHA-1 is used here only because the
   HIBP protocol defines it as the index — it is a bucket key, not password
   storage, so SHA-1's broken collision resistance is irrelevant to this check.
   A "not found" result means the password is absent from HIBP's corpus of
   known breaches — it does NOT mean the password is strong; a short or
   predictable password can be absent and still trivially guessable. A "found"
   count is the number of times the exact password appeared in breach corpora,
   not a count of accounts. If the API cannot be reached, no result is shown
   at all — a failed check is never presented as a clean bill of health. */
(function (root) {
  "use strict";

  var RANGE_URL = "https://api.pwnedpasswords.com/range/";

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

  // SHA-1 hex of the input, UPPERCASE (HIBP uses uppercase hex throughout).
  // Returns a Promise<string> of 40 hex characters.
  function sha1Hex(text) {
    var subtle = getSubtle();
    if (!subtle) return Promise.reject(new Error("WebCrypto is not available in this environment"));
    return subtle.digest("SHA-1", encodeUtf8(text)).then(function (buf) {
      return bytesToHex(buf).toUpperCase();
    });
  }

  // Split a 40-char SHA-1 hex into the 5-char prefix (sent to the API) and the
  // 35-char suffix (matched locally). Returns null for anything malformed.
  function splitHash(hex) {
    if (typeof hex !== "string") return null;
    var h = hex.replace(/\s+/g, "").toUpperCase();
    if (!/^[0-9A-F]{40}$/.test(h)) return null;
    return { prefix: h.slice(0, 5), suffix: h.slice(5) };
  }

  // Parse an HIBP range response ("SUFFIX:COUNT" per line) and return the
  // breach count for the given 35-char suffix, or 0 when it is absent.
  // Matching is case-insensitive; malformed lines are skipped, never fatal.
  function parseRangeResponse(text, suffix) {
    if (typeof text !== "string" || typeof suffix !== "string") return 0;
    var want = suffix.replace(/\s+/g, "").toUpperCase();
    if (!/^[0-9A-F]{35}$/.test(want)) return 0;
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      var parts = line.split(":");
      if (parts.length !== 2) continue;
      var s = parts[0].trim().toUpperCase();
      var n = parseInt(parts[1].trim(), 10);
      if (s === want && !isNaN(n) && n >= 0) return n;
    }
    return 0;
  }

  // Verdict tier for a breach count. "not-found" is only absence from the
  // corpus — the page states plainly that it is not a strength verdict.
  function verdictFor(count) {
    if (typeof count !== "number" || isNaN(count) || count < 0) return "invalid";
    if (count === 0) return "not-found";
    if (count >= 1000000) return "very-common";
    return "found";
  }

  function formatCount(n) {
    return n.toLocaleString("en-US");
  }

  // Full check against the live API. Resolves { count, prefix, suffix, hash }
  // or rejects with an Error (network failure, non-200 status). Never resolves
  // a guessed result.
  function checkPassword(password) {
    if (typeof password !== "string" || password.length === 0) {
      return Promise.reject(new Error("Enter a password to check."));
    }
    return sha1Hex(password).then(function (hex) {
      var parts = splitHash(hex);
      var url = RANGE_URL + parts.prefix;
      var fetchFn = (typeof fetch !== "undefined") ? fetch : null;
      if (!fetchFn) return Promise.reject(new Error("fetch is not available in this environment"));
      return fetchFn(url, { headers: { "Add-Padding": "true" } }).then(function (resp) {
        if (!resp.ok) {
          if (resp.status === 429) throw new Error("The breach database is rate-limiting requests right now (HTTP 429). Wait a minute and try again.");
          throw new Error("The breach database returned HTTP " + resp.status + ". Try again later.");
        }
        return resp.text();
      }).then(function (text) {
        return { count: parseRangeResponse(text, parts.suffix), prefix: parts.prefix, suffix: parts.suffix, hash: hex };
      });
    });
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("breachInput")) return;

    var lastResult = null;

    function setVerdict(kind, html) {
      var v = $("breachVerdict");
      v.innerHTML = html;
      v.className = "verdict " + kind;
      v.hidden = false;
    }

    function run() {
      var pw = $("breachInput").value;
      var btn = $("checkBtn");
      if (!pw) {
        setVerdict("fair", "Type a password above, then press Check.");
        $("breachResult").hidden = true;
        return;
      }
      btn.disabled = true;
      btn.textContent = "Checking…";
      setVerdict("fair", "Hashing locally, then asking the breach database for your hash prefix…");
      $("breachResult").hidden = true;
      $("breachError").hidden = true;
      checkPassword(pw).then(function (res) {
        lastResult = res;
        btn.disabled = false;
        btn.textContent = "Check";
        $("breachHash").textContent = res.hash;
        $("breachPrefix").textContent = res.prefix;
        $("breachSuffix").textContent = res.suffix;
        if (res.count === 0) {
          setVerdict("strong", "NOT FOUND — this password does not appear in the known breach data.");
          $("breachCount").textContent = "0";
          $("breachCountSub").textContent = "times seen in breaches. Absence from the breach list is not proof of strength — a short or predictable password can be absent and still easy to guess. Check its strength on the Strength Checker.";
        } else {
          var tier = verdictFor(res.count);
          setVerdict("critical", "FOUND IN BREACHES — change this password now, everywhere you use it.");
          $("breachCount").textContent = formatCount(res.count);
          $("breachCountSub").textContent = tier === "very-common"
            ? "times seen in breaches. This password is extremely common in leaked data — attackers try it first. Replace it with a fresh one from the Password Generator and turn on two-factor authentication."
            : "times seen in breaches. Anyone with the breach data can look this password up instead of guessing it. Replace it with a fresh one from the Password Generator and turn on two-factor authentication.";
        }
        $("breachResult").hidden = false;
      }).catch(function (e) {
        btn.disabled = false;
        btn.textContent = "Check";
        var err = $("breachError");
        err.textContent = "Check failed: " + e.message + " No result is shown — a failed check is never presented as a clean bill of health.";
        err.hidden = false;
        $("breachVerdict").hidden = true;
      });
    }

    $("checkBtn").addEventListener("click", run);
    $("breachInput").addEventListener("keydown", function (e) {
      if (e.key === "Enter") run();
    });
    $("toggleShowBtn").addEventListener("click", function () {
      var input = $("breachInput");
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      $("toggleShowBtn").textContent = show ? "🙈 Hide" : "👁 Show";
    });
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }

  var api = {
    RANGE_URL: RANGE_URL, sha1Hex: sha1Hex, splitHash: splitHash,
    parseRangeResponse: parseRangeResponse, verdictFor: verdictFor,
    formatCount: formatCount, checkPassword: checkPassword
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.BreachCheck = api;
})(typeof self !== "undefined" ? self : this);
