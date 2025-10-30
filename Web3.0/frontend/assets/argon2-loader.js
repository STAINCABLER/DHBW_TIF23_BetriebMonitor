const encoder = new TextEncoder();

const SOURCES = [
  'https://esm.sh/@noble/hashes@1.4.0/argon2?target=es2020&no-check',
  'https://cdn.jsdelivr.net/npm/@noble/hashes@1.4.0/argon2/+esm',
  'https://cdn.skypack.dev/@noble/hashes@1.4.0/argon2',
];

async function loadArgon2FromSources() {
  const errors = [];
  for (const source of SOURCES) {
    try {
      const module = await import(/* @vite-ignore */ source);
      const candidate = module?.argon2id ?? module?.default?.argon2id ?? module?.default;
      const argon2id = typeof candidate === 'function' ? candidate : module?.argon2id;
      if (typeof argon2id !== 'function') {
        throw new Error('argon2id Export fehlt.');
      }

      const toBytes = (value) => {
        if (value instanceof Uint8Array) {
          return value;
        }
        if (ArrayBuffer.isView(value)) {
          return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        }
        if (value instanceof ArrayBuffer) {
          return new Uint8Array(value);
        }
        if (typeof value === 'string') {
          return encoder.encode(value);
        }
        throw new TypeError('Ungültiger Datentyp für Argon2.');
      };

      const adapter = {
        async hash(options = {}) {
          const {
            pass,
            salt,
            time = 3,
            mem = 64 * 1024,
            parallelism = 4,
            hashLen = 32,
          } = options;
          if (pass === undefined || salt === undefined) {
            throw new Error('Passwort oder Salt fehlt.');
          }
          const passwordBytes = toBytes(pass);
          const saltBytes = toBytes(salt);
          const hash = argon2id(passwordBytes, saltBytes, {
            t: time,
            m: mem,
            p: parallelism,
            dkLen: hashLen,
          });
          return { hash };
        },
      };

      window.AlteBankArgon2 = adapter;
      if (window.ALTEBANK_DEBUG) {
        console.debug('[argon2-loader] Argon2 bereitgestellt aus', source);
      }
      return adapter;
    } catch (error) {
      errors.push({ source, error });
      if (window.ALTEBANK_DEBUG) {
        console.warn('[argon2-loader] Quelle fehlgeschlagen', source, error);
      }
    }
  }

  const message = errors.length
    ? `Argon2 konnte nicht geladen werden (${errors.map((item) => item.source).join(', ')}).`
    : 'Argon2 konnte nicht geladen werden.';
  throw new Error(message);
}

const loadPromise = loadArgon2FromSources().catch((error) => {
  console.error('Argon2 konnte nicht geladen werden:', error);
  delete window.AlteBankArgon2;
  throw error;
});

window.AlteBankArgon2Load = loadPromise;

export default loadPromise;
