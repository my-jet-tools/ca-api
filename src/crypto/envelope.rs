//! The key, and the envelope the data folder keeps everything in: AES-256-GCM. What travels is
//! not this: the encrypted calls are my-http-server's `aes128gcm` bodies.
//!
//! - A key: 32 bytes, written as base64 (standard alphabet, with padding).
//! - An envelope: base64 of `nonce (12 bytes) ‖ ciphertext ‖ tag (16 bytes)`. The nonce is random
//!   for every envelope.
//! - The associated data (AAD) is not in the envelope, but the tag covers it: it says what the
//!   envelope is for, so one made for one purpose does not open for another. It is `state` for the
//!   state in the data folder, and `journal` for a line of the journal.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use data_encoding::BASE64;

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub type Key = [u8; KEY_LEN];

/// A new random key.
pub fn generate_key() -> Result<Key, String> {
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).map_err(|e| format!("no randomness for a key: {e}"))?;
    Ok(key)
}

pub fn encode_key(key: &Key) -> String {
    BASE64.encode(key)
}

/// The key from its base64; whitespace around it is ignored. The error never repeats the key.
pub fn decode_key(raw: &str) -> Result<Key, String> {
    let bytes = BASE64
        .decode(raw.trim().as_bytes())
        .map_err(|_| "the key is not base64".to_string())?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("the key is {len} bytes, not {KEY_LEN}"))
}

pub struct Cipher {
    aead: Aes256Gcm,
}

impl Cipher {
    pub fn new(key: &Key) -> Self {
        Self {
            aead: Aes256Gcm::new_from_slice(key).expect("AES-256-GCM takes a 32-byte key"),
        }
    }

    /// `plain` in an envelope for `aad`.
    pub fn seal(&self, plain: &[u8], aad: &str) -> Result<String, String> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| format!("no randomness for a nonce: {e}"))?;
        let payload = Payload {
            msg: plain,
            aad: aad.as_bytes(),
        };
        let sealed = self
            .aead
            .encrypt(&Nonce::from(nonce), payload)
            .map_err(|_| "encryption failed".to_string())?;
        let mut envelope = Vec::with_capacity(NONCE_LEN + sealed.len());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&sealed);
        Ok(BASE64.encode(&envelope))
    }

    /// What the envelope holds — when it was sealed with this key for `aad` and not changed
    /// since. Whitespace around it is ignored.
    pub fn open(&self, envelope: &str, aad: &str) -> Result<Vec<u8>, String> {
        let raw = BASE64
            .decode(envelope.trim().as_bytes())
            .map_err(|_| "the envelope is not base64".to_string())?;
        if raw.len() < NONCE_LEN + TAG_LEN {
            return Err("the envelope is too short".to_string());
        }
        let (nonce, sealed) = raw.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split at NONCE_LEN");
        let payload = Payload {
            msg: sealed,
            aad: aad.as_bytes(),
        };
        self.aead
            .decrypt(&Nonce::from(nonce), payload)
            .map_err(|_| "the envelope does not open with this key".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_key, encode_key, generate_key, Cipher, KEY_LEN};

    #[test]
    fn an_envelope_opens_with_its_key_for_its_purpose_only() {
        let key = generate_key().unwrap();
        let cipher = Cipher::new(&key);
        let envelope = cipher.seal(b"{\"a\":1}", "state").unwrap();
        assert_eq!(cipher.open(&envelope, "state").unwrap(), b"{\"a\":1}");
        assert!(cipher.open(&envelope, "journal").is_err());
        assert!(Cipher::new(&generate_key().unwrap())
            .open(&envelope, "state")
            .is_err());
        // A nonce per envelope: the same text twice is two different envelopes.
        assert_ne!(envelope, cipher.seal(b"{\"a\":1}", "state").unwrap());
    }

    #[test]
    fn a_changed_envelope_does_not_open() {
        let cipher = Cipher::new(&generate_key().unwrap());
        let envelope = cipher.seal(b"hello", "state").unwrap();
        let mut raw = data_encoding::BASE64.decode(envelope.as_bytes()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(cipher
            .open(&data_encoding::BASE64.encode(&raw), "state")
            .is_err());
        for bad in ["", "not base64!", "AAAA"] {
            assert!(cipher.open(bad, "state").is_err(), "{bad}");
        }
    }

    #[test]
    fn keys_are_base64_of_32_bytes() {
        let key = generate_key().unwrap();
        assert_eq!(decode_key(&format!(" {}\n", encode_key(&key))).unwrap(), key);
        assert!(decode_key("not base64!").is_err());
        assert!(
            decode_key(&data_encoding::BASE64.encode(&[0u8; KEY_LEN - 1]))
                .unwrap_err()
                .contains("31 bytes")
        );
    }
}
