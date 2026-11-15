/* PasswordLab TOTP Authenticator — all computation is local. No network requests.
   TOTP (RFC 6238): a time-based one-time password. The server and your device share
   a secret; both compute HMAC(secret, counter), where counter = floor(unixTime / 30).
   Dynamic truncation takes 4 bytes out of the HMAC (offset = last byte & 0x0f, top bit
   cleared) and the code is that 31-bit value mod 10^digits. The code changes every
   30 seconds, so a 6-digit code is only 1,000,000 possibilities — its security comes
   from the short window plus server rate limiting, not from the code being
   unguessable. That is why the page shows the previous/next codes (clock skew) and
   says plainly: a website can claim anything about not sending your secret, so only
   paste a real secret here if you accept that risk; a dedicated authenticator app is
   the safer home for production secrets. This tool is best for learning, testing,
   and accounts where you understand the trade-off. */
(function (root) {
  "use strict";

  var B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  var DEFAULT_PERIOD = 30;

  function getSubtle() {
    if (root.crypto && root.crypto.subtle) return root.crypto.subtle;
    if (typeof require === "function") {
      try { return require("crypto").webcrypto.subtle; } catch (e) { /* browser: no require */ }
    }
    return null;
  }

  // Base32 (RFC 4648) decode. Tolerates lowercase and spaces; returns null on any
  // invalid character or a length that cannot decode to whole bytes.
  function base32Decode(text) {
    if (typeof text !== "string") return null;
    var clean = text.replace(/[\s=]/g, "").toUpperCase();
    if (clean.length === 0) return null;
    var bits = 0, value = 0, out = [];
    for (var i = 0; i < clean.length; i++) {
      var idx = B32_ALPHABET.indexOf(clean.charAt(i));
      if (idx === -1) return null;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.push((value >>> bits) & 0xff);
      }
    }
    if (bits >= 5) return null; // leftover bits that cannot form a byte: malformed
    return new Uint8Array(out);
  }

  function counterForTime(unixSeconds, period) {
    return Math.floor(unixSeconds / period);
  }

  function counterBytes(counter) {
    var buf = new ArrayBuffer(8);
    var view = new DataView(buf);
    view.setUint32(0, Math.floor(counter / 4294967296));
    view.setUint32(4, counter >>> 0);
    return new Uint8Array(buf);
  }

  function dynamicTruncate(hmacBytes, digits) {
    var offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    var binary = ((hmacBytes[offset] & 0x7f) << 24) |
                 ((hmacBytes[offset + 1] & 0xff) << 16) |
                 ((hmacBytes[offset + 2] & 0xff) << 8) |
                 (hmacBytes[offset + 3] & 0xff);
    var mod = Math.pow(10, digits);
    var code = binary % mod;
    var s = String(code);
    while (s.length < digits) s = "0" + s;
    return s;
  }

  // hmacFn: async (keyBytes, msgBytes, algorithm) -> Uint8Array. Defaults to
  // WebCrypto subtle (browser + node). Injectable so tests can use a sync HMAC.
  function defaultHmac(keyBytes, msgBytes, algorithm) {
    var subtle = getSubtle();
    if (!subtle) return Promise.reject(new Error("WebCrypto is unavailable"));
    var hashName = algorithm === "SHA-256" ? "SHA-256" : algorithm === "SHA-512" ? "SHA-512" : "SHA-1";
    return subtle.importKey("raw", keyBytes, { name: "HMAC", hash: hashName }, false, ["sign"])
      .then(function (key) { return subtle.sign("HMAC", key, msgBytes); })
      .then(function (sig) { return new Uint8Array(sig); });
  }

  function totpAt(keyBytes, unixSeconds, digits, algorithm, period, hmacFn) {
    if (!keyBytes || keyBytes.length === 0) return Promise.resolve(null);
    if (digits !== 6 && digits !== 8) return Promise.resolve(null);
    if (period <= 0) return Promise.resolve(null);
    var counter = counterForTime(unixSeconds, period);
    var fn = hmacFn || defaultHmac;
    return Promise.resolve(fn(keyBytes, counterBytes(counter), algorithm || "SHA-1"))
      .then(function (hmacBytes) { return dynamicTruncate(hmacBytes, digits); });
  }

  function secondsRemaining(unixSeconds, period) {
    var elapsed = unixSeconds % period;
    return period - elapsed;
  }

  function otpauthUri(account, issuer, secret, algorithm, digits, period) {
    var label = issuer ? encodeURIComponent(issuer) + ":" + encodeURIComponent(account || "account")
                       : encodeURIComponent(account || "account");
    var params = "secret=" + secret.replace(/[\s=]/g, "").toUpperCase() +
      "&issuer=" + encodeURIComponent(issuer || "") +
      "&algorithm=" + (algorithm || "SHA1").replace("-", "") +
      "&digits=" + (digits || 6) + "&period=" + (period || 30);
    return "otpauth://totp/" + label + "?" + params;
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

  // A fresh test secret: 16 base32 characters = 80 bits. TOTP security is bounded
  // by the 6-digit code window anyway; 16 characters is the authenticator-app norm.
  function generateSecret(length, rng) {
    rng = rng || defaultRng;
    var out = "";
    for (var i = 0; i < (length || 16); i++) out += B32_ALPHABET.charAt(rng(32));
    return out;
  }

  // ---- DOM wiring (browser only) ----
  function init() {
    var $ = function (id) { return document.getElementById(id); };
    if (!$("totpSecret")) return;
    var timer = null;

    function readOptions() {
      var algo = document.querySelector('input[name="totpAlgo"]:checked');
      var dig = document.querySelector('input[name="totpDigits"]:checked');
      var per = document.querySelector('input[name="totpPeriod"]:checked');
      return {
        algorithm: algo ? algo.value : "SHA-1",
        digits: dig ? parseInt(dig.value, 10) : 6,
        period: per ? parseInt(per.value, 10) : 30
      };
    }

    function showError(msg) {
      var e = $("totpError");
      if (msg) { e.textContent = msg; e.hidden = false; } else { e.hidden = true; }
      $("result").hidden = true;
    }

    function tick() {
      var secret = $("totpSecret").value;
      var key = base32Decode(secret);
      if (!key) { showError("That secret is not valid Base32. Use only A–Z and 2–7 (spaces are ignored)."); return; }
      var opts = readOptions();
      var now = Math.floor(Date.now() / 1000);
      var remain = secondsRemaining(now, opts.period);
      totpAt(key, now, opts.digits, opts.algorithm, opts.period).then(function (code) {
        return Promise.all([
          code,
          totpAt(key, now - opts.period, opts.digits, opts.algorithm, opts.period),
          totpAt(key, now + opts.period, opts.digits, opts.algorithm, opts.period)
        ]);
      }).then(function (codes) {
        showError(null);
        $("codeOut").textContent = codes[0];
        $("prevCode").textContent = codes[1];
        $("nextCode").textContent = codes[2];
        $("timeLeft").textContent = remain + "s left";
        $("progressBar").style.width = (remain / opts.period * 100) + "%";
        var bits = key.length * 8;
        $("secretBits").textContent = key.length + " bytes (" + bits + " bits)";
        $("otpauthUri").textContent = otpauthUri(
          $("totpAccount").value.trim(), $("totpIssuer").value.trim(),
          secret, opts.algorithm, opts.digits, opts.period);
        $("result").hidden = false;
      }).catch(function () {
        showError("This browser cannot compute HMAC (WebCrypto unavailable). Try a modern browser over HTTPS.");
      });
    }

    function restart() {
      if (timer) clearInterval(timer);
      tick();
      timer = setInterval(tick, 1000);
    }

    $("totpSecret").addEventListener("input", restart);
    var inputs = document.querySelectorAll('input[name="totpAlgo"], input[name="totpDigits"], input[name="totpPeriod"]');
    for (var i = 0; i < inputs.length; i++) inputs[i].addEventListener("change", restart);
    $("totpAccount").addEventListener("input", tick);
    $("totpIssuer").addEventListener("input", tick);
    $("genSecretBtn").addEventListener("click", function () {
      $("totpSecret").value = generateSecret(16);
      restart();
    });
    $("copyCodeBtn").addEventListener("click", function () {
      navigator.clipboard.writeText($("codeOut").textContent).then(function () {
        $("copyHint").hidden = false;
        setTimeout(function () { $("copyHint").hidden = true; }, 2500);
      });
    });
    $("copyUriBtn").addEventListener("click", function () {
      navigator.clipboard.writeText($("otpauthUri").textContent).then(function () {
        $("copyUriHint").hidden = false;
        setTimeout(function () { $("copyUriHint").hidden = true; }, 2500);
      });
    });
    // Pre-fill a test secret so the page demonstrates itself immediately.
    $("totpSecret").value = "JBSWY3DPEHPK3PXP";
    restart();
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }

  var api = {
    B32_ALPHABET: B32_ALPHABET, base32Decode: base32Decode,
    counterForTime: counterForTime, counterBytes: counterBytes,
    dynamicTruncate: dynamicTruncate, totpAt: totpAt,
    secondsRemaining: secondsRemaining, otpauthUri: otpauthUri,
    generateSecret: generateSecret
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.TotpGen = api;
})(typeof self !== "undefined" ? self : this);
