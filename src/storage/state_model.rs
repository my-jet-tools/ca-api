//! The state: everything ca-api knows, kept only encrypted, as JSON, in the data folder
//! ([`super::data_folder::DataFolder`]) — every CA with its key, every certificate it issued with
//! its key, the serial counter, and the network key. There is no CRL: my-reverse-proxy reads the
//! serials of the revoked certificates as a list.
//!
//! A certificate is kept by its id — its serial, unique within its CA — never by its CN: issuing
//! the same email again adds a certificate and replaces none, so a revocation is never lost.
//!
//! ```json
//! {"cas":{"xfin-ca":{"cert_pem":"-----BEGIN CERTIFICATE-----…","private_key_pem":"…",
//!   "next_serial":3,
//!   "certificates":[{"cn":"alice@example.com","serial":1,"issued_at":1714000000,
//!     "revoked_at":1714050000,"cert_pem":"…","private_key_pem":"…"}]}},
//!  "network_key":"<base64 of 32 bytes>"}
//! ```

use std::collections::BTreeMap;
use std::io::Write;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateModel {
    /// The CAs by their name — the `caName` of the API.
    #[serde(default)]
    pub cas: BTreeMap<String, CaModel>,
    /// The network key, base64: what the answers to my-reverse-proxy are encrypted with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaModel {
    /// The CA certificate, PEM.
    pub cert_pem: String,
    /// The CA private key, PEM (PKCS#8).
    pub private_key_pem: String,
    /// The serial the next client certificate gets.
    pub next_serial: u64,
    /// Every certificate the CA issued, revoked ones included, in the order issued. The serial is
    /// the id: no two records have the same one.
    #[serde(default)]
    pub certificates: Vec<IssuedCertModel>,
}

impl CaModel {
    pub fn new(cert_pem: String, private_key_pem: String) -> Self {
        Self {
            cert_pem,
            private_key_pem,
            next_serial: 1,
            certificates: Vec::new(),
        }
    }

    /// The certificate with the id `serial`.
    pub fn get(&self, serial: u64) -> Option<&IssuedCertModel> {
        self.certificates.iter().find(|cert| cert.serial == serial)
    }

    /// The serials of the revoked certificates, ascending.
    pub fn revoked_serials(&self) -> Vec<u64> {
        let mut serials: Vec<u64> = self
            .certificates
            .iter()
            .filter(|cert| cert.revoked_at.is_some())
            .map(|cert| cert.serial)
            .collect();
        serials.sort_unstable();
        serials
    }

    /// The newest certificate of `cn` that is not revoked.
    pub fn newest_active(&self, cn: &str) -> Option<&IssuedCertModel> {
        self.certificates
            .iter()
            .filter(|cert| cert.cn == cn && cert.revoked_at.is_none())
            .max_by_key(|cert| cert.serial)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedCertModel {
    /// The common name: the email the certificate was issued for. Several certificates may have
    /// the same one.
    pub cn: String,
    /// The serial: the certificate's id within its CA.
    pub serial: u64,
    /// unix seconds
    pub issued_at: i64,
    /// unix seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    /// The certificate, PEM. `None` only for a record imported from a plaintext folder that had no
    /// file for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    /// The certificate's private key, PEM (PKCS#8); `None` as `cert_pem`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
}

/// Write `content` to `path` atomically — a temporary file next to it, then a rename — readable
/// by the owner only.
pub fn write_atomic(path: &str, content: &[u8]) -> Result<(), String> {
    let tmp_path = format!("{path}.tmp");
    write_private(&tmp_path, content)
        .map_err(|e| format!("the file {tmp_path} cannot be written: {e}"))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("the file {path} cannot be replaced: {e}"))
}

fn write_private(path: &str, content: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(content)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::{CaModel, StateModel};

    #[test]
    fn an_empty_state_is_read_and_written() {
        let state: StateModel = serde_json::from_str("{}").unwrap();
        assert_eq!(state, StateModel::default());
        assert_eq!(serde_json::to_string(&state).unwrap(), r#"{"cas":{}}"#);
    }

    #[test]
    fn a_new_ca_starts_its_serials_at_one() {
        let ca = CaModel::new("cert".to_string(), "key".to_string());
        assert_eq!(ca.next_serial, 1);
        assert!(ca.certificates.is_empty() && ca.revoked_serials().is_empty());
    }

    #[test]
    fn a_state_with_the_crl_of_an_earlier_build_is_read() {
        let state: StateModel = serde_json::from_str(
            r#"{"cas":{"a":{"cert_pem":"c","private_key_pem":"k","next_serial":2,"next_crl_number":3,"crl_pem":"CRL","certificates":[]}}}"#,
        )
        .unwrap();
        assert_eq!(state.cas["a"].next_serial, 2);
    }
}
