const openpgp = require('openpgp');

const BUCKETS = [256, 1024, 8192, 65536];
function pad(text) {
  const s = String(text ?? '');
  const wire = String(s.length).padStart(8, '0') + s;
  const bucket = BUCKETS.find((b) => wire.length <= b) || Math.ceil(wire.length / 65536) * 65536;
  return wire + ' '.repeat(bucket - wire.length);
}

async function encryptText(armoredPublicKey, plaintext) {
  const encryptionKeys = await openpgp.readKey({ armoredKey: armoredPublicKey });
  return openpgp.encrypt({
    message: await openpgp.createMessage({ text: pad(plaintext) }),
    encryptionKeys,
    config: { aeadProtect: true },
  });
}

async function encryptBytes(armoredPublicKey, buf) {
  const encryptionKeys = await openpgp.readKey({ armoredKey: armoredPublicKey });
  const out = await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: new Uint8Array(buf) }),
    encryptionKeys, format: 'binary', config: { aeadProtect: true },
  });
  return Buffer.from(out);
}

module.exports = { encryptText, encryptBytes };
