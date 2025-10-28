(function registerCryptoHelpers(global) {
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function base64ToBytes(value) {
    const normalized = value.replace(/\s+/g, '');
    const binary = window.atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  async function resolveArgon2() {
    if (global.AlteBankArgon2 && typeof global.AlteBankArgon2.hash === 'function') {
      return global.AlteBankArgon2;
    }
    if (global.AlteBankArgon2Load) {
      try {
        const adapter = await global.AlteBankArgon2Load;
        if (adapter && typeof adapter.hash === 'function') {
          return adapter;
        }
      } catch (error) {
        throw new Error(error?.message || 'Argon2 konnte nicht geladen werden');
      }
    }
    throw new Error('Argon2 nicht verfügbar');
  }

  async function deriveKey(password, salt) {
    const argon2 = await resolveArgon2();
    const result = await argon2.hash({
      pass: password,
      salt,
      time: 3,
      mem: 64 * 1024,
      parallelism: 4,
      hashLen: 32,
    });
    return new Uint8Array(result.hash);
  }

  async function decryptPrivateKey(encryptedPayload, password) {
    if (!encryptedPayload || typeof encryptedPayload !== 'object') {
      throw new Error('Ungültiges Schlüsselmaterial');
    }
    const salt = base64ToBytes(encryptedPayload.salt || '');
    const nonce = base64ToBytes(encryptedPayload.nonce || '');
    const ciphertext = base64ToBytes(encryptedPayload.ciphertext || '');

    const keyBytes = await deriveKey(password, salt);
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, ciphertext);
    return new Uint8Array(plainBuffer);
  }

  function buildSigningKey(privateSeedBytes) {
    if (!global.nacl || !global.nacl.sign) {
      throw new Error('Signaturbibliothek nicht verfügbar');
    }
    if (!(privateSeedBytes instanceof Uint8Array) || privateSeedBytes.length !== 32) {
      throw new Error('Ungültiger privater Seed');
    }
    return global.nacl.sign.keyPair.fromSeed(privateSeedBytes);
  }

  function toCanonicalJson(payload) {
    const keys = Object.keys(payload).sort();
    const parts = keys.map((key) => `${JSON.stringify(key)}:${JSON.stringify(payload[key])}`);
    return `{${parts.join(',')}}`;
  }

  function signDetached(privateSeedBytes, messagePayload) {
    const keyPair = buildSigningKey(privateSeedBytes);
    const canonical = toCanonicalJson(messagePayload);
    const messageBytes = textEncoder.encode(canonical);
    const signatureBytes = global.nacl.sign.detached(messageBytes, keyPair.secretKey);
    return {
      signature: bytesToBase64(signatureBytes),
      messageBytes,
      canonical,
    };
  }

  global.AlteBankCrypto = {
    base64ToBytes,
    bytesToBase64,
    decryptPrivateKey,
    signDetached,
    buildSigningKey,
    toCanonicalJson,
    textEncoder,
    textDecoder,
  };
})(window);
