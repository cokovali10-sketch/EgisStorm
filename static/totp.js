const Totp = (() => {
  const ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const PERIOD = 30;

  function b32decode(s) {
    s = s.toUpperCase().replace(/[^A-Z2-7]/g, "");
    let bits = 0, val = 0;
    const out = [];
    for (const ch of s) {
      val = (val << 5) | ALPH.indexOf(ch);
      bits += 5;
      if (bits >= 8) {
        out.push((val >> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  async function hmac(keyBytes, msgBytes) {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
    return new Uint8Array(sig);
  }

  async function code(secret, now = new Date()) {
    let counter = Math.floor(now.getTime() / 1000 / PERIOD);
    const msg = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
      msg[i] = counter & 0xff;
      counter = Math.floor(counter / 256);
    }
    const sig = await hmac(b32decode(secret), msg);
    const offset = sig[sig.length - 1] & 0xf;
    const bin =
      ((sig[offset] & 0x7f) << 24) |
      (sig[offset + 1] << 16) |
      (sig[offset + 2] << 8) |
      sig[offset + 3];
    return { code: String(bin % 1000000).padStart(6, "0"), period: PERIOD };
  }

  return { code };
})();