// vim: ts=4:sw=4

"use strict";

const nodeCrypto = require("crypto");
const signal = require("@skidy89/libsignal-plugins");
// Salts always end up being 32 bytes
function deriveSecrets(input, salt, info, chunks) {
  // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
  assertBuffer(input);
  assertBuffer(salt);
  assertBuffer(info);
  if (salt.byteLength != 32) {
    throw new Error("Got salt of incorrect length");
  }
  return signal.deriveSecrets(input, salt, info, chunks);
}
function assertBuffer(value) {
  if (!(value instanceof Buffer)) {
    throw TypeError(`Expected Buffer instead of: ${value.constructor.name}`);
  }
  return value;
}

function encrypt(key, data, iv) {
  assertBuffer(key);
  assertBuffer(data);
  assertBuffer(iv);
  const cipher = nodeCrypto.createCipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function decrypt(key, data, iv) {
  assertBuffer(key);
  assertBuffer(data);
  assertBuffer(iv);
  const decipher = nodeCrypto.createDecipheriv("aes-256-cbc", key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function calculateMAC(key, data) {
  assertBuffer(key);
  assertBuffer(data);
  const hmac = nodeCrypto.createHmac("sha256", key);
  hmac.update(data);
  return Buffer.from(hmac.digest());
}

function hash(data) {
  assertBuffer(data);
  const sha512 = nodeCrypto.createHash("sha512");
  sha512.update(data);
  return sha512.digest();
}



function verifyMAC(data, key, mac, length) {
  const calculatedMac = calculateMAC(key, data).slice(0, length);
  if (mac.length !== length || calculatedMac.length !== length) {
    throw new Error("Bad MAC length");
  }
  if (!mac.equals(calculatedMac)) {
    throw new Error("Bad MAC");
  }
}

module.exports = {
  decrypt,
  encrypt,
  hash,
  calculateMAC,
  verifyMAC,
  deriveSecrets,
};
