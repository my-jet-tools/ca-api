//! The plaintext PKI folder of ca-api 0.2 (`config_path` of the settings), read once — into the
//! state the first key creates. The folder itself is only read, never changed: deleting it once
//! the import is checked is the operator's call.
//!
//! ```text
//! {config_path}/{caName}/ca_cert.pem, ca_private_key.pem, serial, index.json  (crl_number, crl.pem: not needed)
//! {config_path}/{caName}/certs/{email with @ as _}/cert.pem, private_key.pem
//! ```
//!
//! A folder without `ca_cert.pem` is not a CA and is passed over, as 0.2 did. Anything else that
//! cannot be read — a CA without its key, a broken `index.json`, a counter that is not a number —
//! stops the import, so that nothing is lost silently: no revocation, no serial.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use super::state_model::{CaModel, IssuedCertModel};

/// A record of 0.2's `index.json`.
#[derive(Deserialize)]
struct IndexRecord {
    cn: String,
    serial: u64,
    issued_at: i64,
    #[serde(default)]
    revoked_at: Option<i64>,
}

/// The CAs of the plaintext folder at `folder`, by name. A folder that does not exist has none.
pub fn read_legacy_pki(folder: &str) -> Result<BTreeMap<String, CaModel>, String> {
    let mut cas = BTreeMap::new();
    let entries = match std::fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(cas),
        Err(e) => return Err(format!("the PKI folder {folder} cannot be read: {e}")),
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("the PKI folder {folder} cannot be read: {e}"))?;
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir {
            continue;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let dir = entry.path();
        if !dir.join("ca_cert.pem").exists() {
            continue;
        }
        cas.insert(name, read_ca(&dir)?);
    }
    Ok(cas)
}

fn read_ca(dir: &Path) -> Result<CaModel, String> {
    let cert_pem = read_required(&dir.join("ca_cert.pem"))?;
    let private_key_pem = read_required(&dir.join("ca_private_key.pem"))?;
    let key_pair = rcgen::KeyPair::from_pem(&private_key_pem)
        .map_err(|e| format!("{}: not a private key: {e}", dir.display()))?;
    rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair)
        .map_err(|e| format!("{}: not a CA certificate with its key: {e}", dir.display()))?;

    let index: Vec<IndexRecord> = match read_optional(&dir.join("index.json"))? {
        Some(text) if !text.trim().is_empty() => serde_json::from_str(&text)
            .map_err(|e| format!("{}: index.json is invalid: {e}", dir.display()))?,
        _ => Vec::new(),
    };

    let mut certificates = Vec::with_capacity(index.len());
    for record in index {
        let cert_dir = dir.join("certs").join(record.cn.replace('@', "_"));
        certificates.push(IssuedCertModel {
            cert_pem: read_optional(&cert_dir.join("cert.pem"))?,
            private_key_pem: read_optional(&cert_dir.join("private_key.pem"))?,
            cn: record.cn,
            serial: record.serial,
            issued_at: record.issued_at,
            revoked_at: record.revoked_at,
        });
    }

    // The serial is a certificate's id: two records with one would be one certificate twice.
    let mut serials: Vec<u64> = certificates.iter().map(|cert| cert.serial).collect();
    serials.sort_unstable();
    if let Some(pair) = serials.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(format!(
            "{}: index.json has serial {} twice",
            dir.display(),
            pair[0]
        ));
    }

    // Never a serial that was given already: past the highest issued one, whatever the file says.
    let issued_past = certificates
        .iter()
        .map(|cert| cert.serial.saturating_add(1))
        .max()
        .unwrap_or(1);
    let next_serial = read_counter(&dir.join("serial"))?.max(issued_past);

    Ok(CaModel {
        cert_pem,
        private_key_pem,
        next_serial,
        certificates,
    })
}

/// A counter file of 0.2: the next number, decimal. 1 when there is none.
fn read_counter(path: &Path) -> Result<u64, String> {
    match read_optional(path)? {
        None => Ok(1),
        Some(text) => text
            .trim()
            .parse::<u64>()
            .map(|n| n.max(1))
            .map_err(|_| format!("{}: not a number", path.display())),
    }
}

fn read_required(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{} cannot be read: {e}", path.display()))
}

fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} cannot be read: {e}", path.display())),
    }
}

#[cfg(test)]
pub mod tests {
    use super::read_legacy_pki;
    use crate::storage::data_folder::tests::Folder;

    /// A plaintext folder as 0.2 wrote it, with one CA.
    pub fn write_legacy_ca(root: &str, name: &str) -> crate::crypto::GeneratedCa {
        let ca = crate::crypto::build_ca(&crate::pem::PemCertInfo {
            ca_cn: name.to_string(),
            organization: "Org".to_string(),
            country_code: "UA".to_string(),
            city: "Kyiv".to_string(),
        })
        .unwrap();
        let dir = format!("{root}/{name}");
        std::fs::create_dir_all(format!("{dir}/certs/alice_example.com")).unwrap();
        std::fs::write(format!("{dir}/ca_cert.pem"), &ca.cert_pem).unwrap();
        std::fs::write(format!("{dir}/ca_private_key.pem"), &ca.key_pem).unwrap();
        std::fs::write(format!("{dir}/serial"), "2").unwrap();
        std::fs::write(format!("{dir}/crl_number"), "4\n").unwrap();
        std::fs::write(format!("{dir}/crl.pem"), "CRL").unwrap();
        std::fs::write(
            format!("{dir}/index.json"),
            r#"[{"cn":"alice@example.com","serial":1,"issued_at":10,"revoked_at":null},
                {"cn":"bob@example.com","serial":5,"issued_at":20,"revoked_at":30}]"#,
        )
        .unwrap();
        std::fs::write(format!("{dir}/certs/alice_example.com/cert.pem"), "A-CERT").unwrap();
        std::fs::write(format!("{dir}/certs/alice_example.com/private_key.pem"), "A-KEY").unwrap();
        ca
    }

    #[test]
    fn a_plaintext_folder_is_read_whole() {
        let folder = Folder::new();
        let ca = write_legacy_ca(&folder.0, "xfin-ca");
        std::fs::create_dir_all(format!("{}/not-a-ca", folder.0)).unwrap();
        std::fs::write(format!("{}/stray.txt", folder.0), "x").unwrap();

        let cas = read_legacy_pki(&folder.0).unwrap();
        assert_eq!(cas.keys().collect::<Vec<_>>(), ["xfin-ca"]);
        let imported = &cas["xfin-ca"];
        assert_eq!(imported.cert_pem, ca.cert_pem);
        assert_eq!(imported.private_key_pem, ca.key_pem);
        // The file said 2, but serial 5 was issued: the next one is past it.
        assert_eq!(imported.next_serial, 6);
        assert_eq!(imported.revoked_serials(), [5]);
        let alice = imported.get(1).unwrap();
        assert_eq!(alice.cn, "alice@example.com");
        assert_eq!(alice.cert_pem.as_deref(), Some("A-CERT"));
        assert_eq!(alice.private_key_pem.as_deref(), Some("A-KEY"));
        let bob = imported.get(5).unwrap();
        assert!(imported.newest_active("bob@example.com").is_none());
        assert_eq!((bob.serial, bob.revoked_at, bob.cert_pem.as_deref()), (5, Some(30), None));

        // Read only: the folder is as it was.
        assert!(std::path::Path::new(&format!("{}/xfin-ca/ca_private_key.pem", folder.0)).exists());
    }

    #[test]
    fn what_cannot_be_read_stops_the_import() {
        let folder = Folder::new();
        assert!(read_legacy_pki(&folder.0).unwrap().is_empty());
        write_legacy_ca(&folder.0, "xfin-ca");
        std::fs::write(format!("{}/xfin-ca/index.json", folder.0), "not json").unwrap();
        assert!(read_legacy_pki(&folder.0).unwrap_err().contains("index.json"));
        std::fs::write(
            format!("{}/xfin-ca/index.json", folder.0),
            r#"[{"cn":"a","serial":3,"issued_at":1},{"cn":"b","serial":3,"issued_at":2}]"#,
        )
        .unwrap();
        assert!(read_legacy_pki(&folder.0).unwrap_err().contains("serial 3 twice"));
        std::fs::remove_file(format!("{}/xfin-ca/index.json", folder.0)).unwrap();
        std::fs::write(format!("{}/xfin-ca/serial", folder.0), "x").unwrap();
        assert!(read_legacy_pki(&folder.0).unwrap_err().contains("not a number"));
        std::fs::write(format!("{}/xfin-ca/serial", folder.0), "1").unwrap();
        std::fs::remove_file(format!("{}/xfin-ca/ca_private_key.pem", folder.0)).unwrap();
        assert!(read_legacy_pki(&folder.0).unwrap_err().contains("ca_private_key.pem"));
    }
}
