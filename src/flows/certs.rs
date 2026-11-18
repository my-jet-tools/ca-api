use crate::app::AppContext;
use crate::storage::journal::{JournalEvent, JournalRecord};
use crate::storage::IssuedCertModel;

use super::{blocking, now, validate_name, FlowError};

pub struct IssuedCertificateInfo {
    /// The serial: the certificate's id within its CA.
    pub id: u64,
    pub cn: String,
    pub issued_at: i64,
    pub revoked_at: Option<i64>,
}

/// Which certificate a call is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertSelector {
    /// The certificate with this id (its serial).
    Id(u64),
    /// By its CN — for revoking: every certificate of the CN that is not revoked; for handing
    /// out: the newest of them.
    Cn(String),
}

impl CertSelector {
    /// `id` when there is one, else `email`; one of the two is required. When both are given,
    /// the certificate `id` must be one of `email`.
    pub fn of(id: Option<u64>, email: Option<String>) -> Result<(Self, Option<String>), FlowError> {
        let email = email.map(|email| email.trim().to_string()).filter(|email| !email.is_empty());
        match (id, email) {
            (Some(id), email) => Ok((Self::Id(id), email)),
            (None, Some(email)) => Ok((Self::Cn(email), None)),
            (None, None) => Err(FlowError::ValidationError(
                "the certificate is named by its id (or by email)".to_string(),
            )),
        }
    }
}

/// Issue `email` a client certificate signed by the CA: CN = `email`, RSA-4096, 10 years. Always a
/// new certificate under a new id: one the CN has already stays as it is. Returns the id.
pub async fn generate_cert(app: &AppContext, ca_name: &str, email: &str) -> Result<u64, FlowError> {
    validate_name("email", email)?;
    // Held while the key is made, so that no two certificates get one serial.
    let mut opened = app.storage.lock().await?;
    let ca = opened
        .state()
        .cas
        .get(ca_name)
        .ok_or(FlowError::CaNotFound)?;
    let serial = ca.next_serial;
    if ca.get(serial).is_some() {
        return Err(FlowError::SomethingWentWrong(
            "the next serial is taken already".to_string(),
        ));
    }
    let (ca_cert_pem, ca_key_pem, cn) = (
        ca.cert_pem.clone(),
        ca.private_key_pem.clone(),
        email.to_string(),
    );
    let generated = blocking(move || {
        let issuer = crate::crypto::build_issuer(&ca_cert_pem, &ca_key_pem)?;
        crate::crypto::build_client_cert(&issuer, &cn, serial)
    })
    .await?;

    let mut state = opened.state().clone();
    let ca = state.cas.get_mut(ca_name).ok_or(FlowError::CaNotFound)?;
    ca.next_serial = serial
        .checked_add(1)
        .ok_or_else(|| FlowError::SomethingWentWrong("Serial counter overflow".to_string()))?;
    ca.certificates.push(IssuedCertModel {
        cn: email.to_string(),
        serial,
        issued_at: now(),
        revoked_at: None,
        cert_pem: Some(generated.cert_pem),
        private_key_pem: Some(generated.key_pem),
    });
    opened
        .commit(state)
        .map_err(FlowError::SomethingWentWrong)?;
    opened.journal(JournalRecord::of_cert(
        JournalEvent::CertIssued,
        ca_name,
        email,
        serial,
    ));
    crate::log::info("A client certificate is issued");
    Ok(serial)
}

/// Revoke what `selector` names: from now on its serial is in the list my-reverse-proxy refuses.
/// Returns the ids revoked.
///
/// - [`CertSelector::Id`]: that certificate — `CertAlreadyRevoked` when it is; with `email`, it
///   must be one of that CN.
/// - [`CertSelector::Cn`]: every certificate of the CN that is not revoked yet.
pub async fn revoke_cert(
    app: &AppContext,
    ca_name: &str,
    selector: &CertSelector,
    email: Option<&str>,
) -> Result<Vec<u64>, FlowError> {
    let mut opened = app.storage.lock().await?;
    let mut state = opened.state().clone();
    let ca = state.cas.get_mut(ca_name).ok_or(FlowError::CaNotFound)?;
    let revoked_at = now();
    let mut revoked = Vec::new();
    match selector {
        CertSelector::Id(id) => {
            let cert = ca
                .certificates
                .iter_mut()
                .find(|cert| cert.serial == *id && email.is_none_or(|email| cert.cn == email))
                .ok_or(FlowError::CertNotFound)?;
            if cert.revoked_at.is_some() {
                return Err(FlowError::CertAlreadyRevoked);
            }
            cert.revoked_at = Some(revoked_at);
            revoked.push(cert.serial);
        }
        CertSelector::Cn(cn) => {
            for cert in ca
                .certificates
                .iter_mut()
                .filter(|cert| cert.cn == *cn && cert.revoked_at.is_none())
            {
                cert.revoked_at = Some(revoked_at);
                revoked.push(cert.serial);
            }
            if revoked.is_empty() {
                return Err(FlowError::CertNotFound);
            }
        }
    }
    let cns: Vec<(u64, String)> = ca
        .certificates
        .iter()
        .filter(|cert| revoked.contains(&cert.serial))
        .map(|cert| (cert.serial, cert.cn.clone()))
        .collect();
    opened
        .commit(state)
        .map_err(FlowError::SomethingWentWrong)?;
    for (serial, cn) in cns {
        opened.journal(JournalRecord::of_cert(
            JournalEvent::CertRevoked,
            ca_name,
            &cn,
            serial,
        ));
    }
    crate::log::info(format!(
        "{} client certificate(s) revoked",
        revoked.len()
    ));
    Ok(revoked)
}

/// What `selector` names as PKCS#12 — the certificate, its private key and the CA — protected by
/// `password`: the certificate with the id, revoked or not, or the newest of the CN that is not
/// revoked. Returns its id too. Journaled.
pub async fn get_p12(
    app: &AppContext,
    ca_name: &str,
    selector: &CertSelector,
    email: Option<&str>,
    password: &str,
) -> Result<(u64, Vec<u8>), FlowError> {
    let opened = app.storage.lock().await?;
    let ca = opened
        .state()
        .cas
        .get(ca_name)
        .ok_or(FlowError::CaNotFound)?;
    let cert = match selector {
        CertSelector::Id(id) => ca
            .get(*id)
            .filter(|cert| email.is_none_or(|email| cert.cn == email)),
        CertSelector::Cn(cn) => ca.newest_active(cn),
    }
    .ok_or(FlowError::CertNotFound)?;
    let (Some(cert_pem), Some(key_pem)) = (cert.cert_pem.as_deref(), cert.private_key_pem.as_deref())
    else {
        return Err(FlowError::CertNotFound);
    };
    let p12 = crate::crypto::build_p12(
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
        ca.cert_pem.as_bytes(),
        &cert.cn,
        password,
    )
    .map_err(FlowError::SomethingWentWrong)?;
    opened.journal(JournalRecord::of_cert(
        JournalEvent::PfxDownloaded,
        ca_name,
        &cert.cn,
        cert.serial,
    ));
    crate::log::info("A client certificate is handed out as PKCS#12");
    Ok((cert.serial, p12))
}

/// Every certificate the CA issued, revoked ones included, in the order issued. A CA that does not
/// exist has issued nothing.
pub async fn list_issued_certificates(
    app: &AppContext,
    ca_name: &str,
) -> Result<Vec<IssuedCertificateInfo>, FlowError> {
    let opened = app.storage.lock().await?;
    let Some(ca) = opened.state().cas.get(ca_name) else {
        return Ok(Vec::new());
    };
    Ok(ca
        .certificates
        .iter()
        .map(|cert| IssuedCertificateInfo {
            id: cert.serial,
            cn: cert.cn.clone(),
            issued_at: cert.issued_at,
            revoked_at: cert.revoked_at,
        })
        .collect())
}
