// The slice of 1Password's crypto the fixture tools need: Secret Key parsing, master key
// derivation and the A256GCM opdata envelope. Mirrors account_key.rs, kdf.rs and opdata.rs.

import { createCipheriv, createDecipheriv, hkdfSync, pbkdf2Sync } from "node:crypto";

// Base32 without the confusable characters. The web client drops everything else from the input.
const SECRET_KEY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTVWXYZ";
const SECRET_KEY_LENGTH = 34;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;

export function parseSecretKey(input) {
  const key = [...input.toUpperCase()].filter((c) => SECRET_KEY_ALPHABET.includes(c)).join("");
  if (!key.startsWith("A3") || key.length !== SECRET_KEY_LENGTH) {
    throw new Error(
      `invalid Secret Key: expected A3 and ${SECRET_KEY_LENGTH} characters, got ${key.length}`,
    );
  }
  return { format: key.slice(0, 2), uuid: key.slice(2, 8), key: key.slice(8) };
}

function hkdf(info, ikm, salt) {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, KEY_LENGTH));
}

// The master unlock key, kid "mp". Modern prefix only: no capture uses the legacy one.
export function deriveMasterKey({ email, password, secretKey }, { alg, p2s, p2c }) {
  if (alg !== "PBES2g-HS256") {
    throw new Error(`unsupported key derivation: ${alg}`);
  }
  const username = email.trim().toLowerCase();
  const salt = hkdf(alg, Buffer.from(p2s, "base64url"), Buffer.from(username));
  const derived = pbkdf2Sync(password.trim().normalize("NFKD"), salt, p2c, KEY_LENGTH, "sha256");
  const { format, uuid, key } = parseSecretKey(secretKey);
  const hashed = hkdf(format, Buffer.from(key), Buffer.from(uuid));
  return hashed.map((byte, i) => byte ^ derived[i]);
}

// Decrypts an envelope's `data`, which is `ciphertext || tag` in base64url.
export function openEnvelope(key, { enc, iv, data }) {
  if (enc !== "A256GCM") {
    throw new Error(`unsupported encryption scheme: ${enc}`);
  }
  const bytes = Buffer.from(data, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(bytes.subarray(-TAG_LENGTH));
  const plaintext = decipher.update(bytes.subarray(0, -TAG_LENGTH));
  try {
    return Buffer.concat([plaintext, decipher.final()]);
  } catch {
    throw new Error("the key does not open the envelope");
  }
}

// The inverse: `plaintext` sealed under `key` with the envelope's own IV.
export function sealEnvelope(key, { iv }, plaintext) {
  const cipher = createCipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  const sealed = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return sealed.toString("base64url");
}
