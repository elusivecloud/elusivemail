use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result};
use napi_derive::napi;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};

static KEY: OnceLock<[u8; 32]> = OnceLock::new();

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn key() -> Result<&'static [u8; 32]> {
    KEY.get()
        .ok_or_else(|| Error::from_reason("crypto-core: init(keyHex) not called"))
}

fn cipher() -> Result<Aes256Gcm> {
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key()?)))
}

#[napi]
pub fn init(key_hex: String) -> Result<()> {
    let bytes = hex::decode(key_hex.trim())
        .map_err(|_| Error::from_reason("crypto-core: key must be hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::from_reason("crypto-core: key must be 32 bytes (64 hex chars)"))?;
    let _ = KEY.set(arr);
    Ok(())
}

fn seal(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let ct_tag = cipher()?
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .map_err(|_| Error::from_reason("crypto-core: encrypt failed"))?;
    let split = ct_tag.len() - 16;
    let (ct, tag) = ct_tag.split_at(split);
    let mut out = Vec::with_capacity(28 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ct);
    Ok(out)
}

fn open(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 28 {
        return Err(Error::from_reason("crypto-core: ciphertext too short"));
    }
    let (iv, rest) = raw.split_at(12);
    let (tag, ct) = rest.split_at(16);
    let mut ct_tag = Vec::with_capacity(ct.len() + 16);
    ct_tag.extend_from_slice(ct);
    ct_tag.extend_from_slice(tag);
    cipher()?
        .decrypt(Nonce::from_slice(iv), ct_tag.as_slice())
        .map_err(|_| Error::from_reason("crypto-core: decrypt/auth failed"))
}

#[napi]
pub fn encrypt(plaintext: String) -> Result<String> {
    Ok(B64.encode(seal(plaintext.as_bytes())?))
}

#[napi]
pub fn decrypt(payload: String) -> Result<String> {
    if payload.is_empty() {
        return Ok(String::new());
    }
    let raw = B64
        .decode(payload)
        .map_err(|_| Error::from_reason("crypto-core: bad base64"))?;
    String::from_utf8(open(&raw)?).map_err(|_| Error::from_reason("crypto-core: bad utf8"))
}

#[napi]
pub fn encrypt_bytes(buf: Buffer) -> Result<Buffer> {
    Ok(seal(&buf)?.into())
}

#[napi]
pub fn decrypt_bytes(buf: Buffer) -> Result<Buffer> {
    Ok(open(&buf)?.into())
}

#[napi]
pub fn sha256_hex(input: String) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn base32_decode(secret: &str) -> Vec<u8> {
    let mut bits = String::new();
    for c in secret.trim_end_matches('=').to_uppercase().bytes() {
        if let Some(v) = B32.iter().position(|&x| x == c) {
            bits.push_str(&format!("{:05b}", v));
        }
    }
    bits.as_bytes()
        .chunks_exact(8)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 2).unwrap())
        .collect()
}

fn hotp(secret: &str, counter: u64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&base32_decode(secret)).expect("hmac key");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24)
        | ((h[off + 1] as u32) << 16)
        | ((h[off + 2] as u32) << 8)
        | (h[off + 3] as u32);
    format!("{:06}", bin % 1_000_000)
}

fn step(now_ms: f64) -> i64 {
    (now_ms / 1000.0 / 30.0).floor() as i64
}

#[napi]
pub fn totp_random_secret() -> String {
    let mut buf = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut buf);
    data_encoding::BASE32_NOPAD.encode(&buf)
}

#[napi]
pub fn totp_verify(secret: String, code: String, now_ms: f64) -> bool {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let s = step(now_ms);
    (-1..=1).any(|w| ct_eq(hotp(&secret, (s + w) as u64).as_bytes(), code.as_bytes()))
}

#[napi]
pub fn totp_generate(secret: String, now_ms: f64) -> String {
    hotp(&secret, step(now_ms) as u64)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_roundtrip() {
        init("00".repeat(32)).unwrap();
        let ct = encrypt("hello".into()).unwrap();
        assert_eq!(decrypt(ct).unwrap(), "hello");
        assert_eq!(decrypt(String::new()).unwrap(), "");
    }

    #[test]
    fn totp_tolerance() {
        let s = totp_random_secret();
        let now = 1_700_000_000_000.0;
        let cur = totp_generate(s.clone(), now);
        assert!(totp_verify(s.clone(), cur.clone(), now));
        assert!(!totp_verify(s, cur, now + 120_000.0));
    }
}
