"use strict";
const enc = new TextEncoder();
const CFG = () => ({ s2kType: openpgp.enums.s2k.argon2, aeadProtect: true });
function unpad(wire) {
  if (typeof wire !== "string" || wire.length < 8) return wire;
  const n = parseInt(wire.slice(0, 8), 10);
  if (Number.isNaN(n)) return wire;
  return wire.slice(8, 8 + n);
}
async function sha256hex(str) {
  const h = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function deriveAuth(username, password) {
  return sha256hex(String(username || "").toLowerCase() + ":" + String(password || ""));
}
function makeRecoveryCode() {
  const alpha = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const bytes = crypto.getRandomValues(new Uint8Array(25));
  return [...bytes].map((b) => alpha[b % 32]).join("").replace(/(.{5})(?=.)/g, "$1-");
}
async function unlock(armoredLocked, passphrase) {
  return openpgp.decryptKey({
    privateKey: await openpgp.readPrivateKey({ armoredKey: armoredLocked }),
    passphrase
  });
}
async function relock(unlockedKey, passphrase) {
  return (await openpgp.encryptKey({ privateKey: unlockedKey, passphrase, config: CFG() })).armor();
}
async function fingerprint(armoredPublicKey) {
  const key = await openpgp.readKey({ armoredKey: armoredPublicKey });
  return key.getFingerprint().toUpperCase().replace(/(.{4})(?=.)/g, "$1 ");
}
async function createIdentity(username, password) {
  const { privateKey, publicKey } = await openpgp.generateKey({
    userIDs: [{ name: String(username || "elusive") }],
    type: "ecc",
    curve: "curve25519",
    passphrase: password,
    config: CFG()
  });
  const recoveryCode = makeRecoveryCode();
  const unlocked = await unlock(privateKey, password);
  return {
    recoveryCode,
    publicKey,
    encPrivateKey: privateKey,
    encPrivateKeyRecovery: await relock(unlocked, recoveryCode),
    recoveryHash: await sha256hex(recoveryCode),
    sessionKey: unlocked.armor()
  };
}
async function unlockKey(armoredLocked, passphrase) {
  return (await unlock(armoredLocked, passphrase)).armor();
}
async function rewrapKey(armoredLocked, recoveryCode, newPassword) {
  return relock(await unlock(armoredLocked, recoveryCode), newPassword);
}
async function loadKey(armoredUnlocked) {
  return openpgp.readPrivateKey({ armoredKey: armoredUnlocked });
}
async function serverCustodyMaterial(armoredUnlocked, passphrase) {
  const key = await openpgp.readPrivateKey({ armoredKey: armoredUnlocked });
  const recoveryCode = makeRecoveryCode();
  return {
    encPrivateKey: await relock(key, passphrase),
    encPrivateKeyRecovery: await relock(key, recoveryCode),
    recoveryHash: await sha256hex(recoveryCode),
    recoveryCode
  };
}
async function decryptMessage(key, armoredSubject, armoredBody) {
  const one = async (armored) => {
    if (!armored) return "";
    const { data } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: armored }),
      decryptionKeys: key
    });
    return unpad(data);
  };
  return { subject: await one(armoredSubject), body: await one(armoredBody) };
}
async function newRecovery(armoredUnlocked) {
  const key = await openpgp.readPrivateKey({ armoredKey: armoredUnlocked });
  const recoveryCode = makeRecoveryCode();
  return {
    encPrivateKeyRecovery: await relock(key, recoveryCode),
    recoveryHash: await sha256hex(recoveryCode),
    recoveryCode
  };
}
async function decryptAttachment(key, ciphertextBytes) {
  const message = await openpgp.readMessage({ binaryMessage: ciphertextBytes });
  const { data } = await openpgp.decrypt({ message, decryptionKeys: key, format: "binary" });
  return data;
}
async function generatePrekeys(identityPublicKey, count) {
  const recipient = await openpgp.readKey({ armoredKey: identityPublicKey });
  const out = [];
  for (let i = 0; i < count; i++) {
    const { privateKey, publicKey } = await openpgp.generateKey({
      userIDs: [{ name: "prekey" }], type: "ecc", curve: "curve25519", config: CFG()
    });
    const encPrivateKey = await openpgp.encrypt({
      message: await openpgp.createMessage({ text: privateKey }),
      encryptionKeys: recipient,
      config: { aeadProtect: true }
    });
    out.push({ publicKey, encPrivateKey });
  }
  return out;
}
async function unwrapPrekey(identityPrivateKey, encPrivateKey) {
  const { data } = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: encPrivateKey }),
    decryptionKeys: identityPrivateKey
  });
  return openpgp.readPrivateKey({ armoredKey: data });
}
window.ElusiveCrypto = {
  sha256hex, deriveAuth, fingerprint, createIdentity, unlockKey, rewrapKey, loadKey,
  serverCustodyMaterial, newRecovery, decryptAttachment, decryptMessage,
  generatePrekeys, unwrapPrekey
};
