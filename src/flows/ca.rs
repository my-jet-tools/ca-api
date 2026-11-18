use crate::app::AppContext;
use crate::storage::journal::{JournalEvent, JournalRecord};
use crate::storage::CaModel;

use super::{blocking, validate_name, FlowError, PemCertInfo};

/// The names of the CAs.
pub async fn list_cas(app: &AppContext) -> Result<Vec<String>, FlowError> {
    let opened = app.storage.lock().await?;
    Ok(opened.state().cas.keys().cloned().collect())
}

pub async fn check_ca(app: &AppContext, ca_name: &str) -> Result<(), FlowError> {
    let opened = app.storage.lock().await?;
    if opened.state().cas.contains_key(ca_name) {
        Ok(())
    } else {
        Err(FlowError::CaNotFound)
    }
}

/// A new CA under `info.ca_cn`: RSA-4096, 10 years.
pub async fn generate_ca(app: &AppContext, info: PemCertInfo) -> Result<(), FlowError> {
    validate_name("caName", &info.ca_cn)?;
    let ca_name = info.ca_cn.clone();
    if app.storage.lock().await?.state().cas.contains_key(&ca_name) {
        return Err(FlowError::CaAlreadyGenerated);
    }
    // The key is made without holding the state: it takes seconds.
    let generated = blocking(move || crate::crypto::build_ca(&info)).await?;

    let mut opened = app.storage.lock().await?;
    let mut state = opened.state().clone();
    if state.cas.contains_key(&ca_name) {
        return Err(FlowError::CaAlreadyGenerated);
    }
    state.cas.insert(
        ca_name.clone(),
        CaModel::new(generated.cert_pem, generated.key_pem),
    );
    opened
        .commit(state)
        .map_err(FlowError::SomethingWentWrong)?;
    opened.journal(JournalRecord::of_ca(JournalEvent::CaGenerated, &ca_name));
    crate::log::info("A CA is generated");
    Ok(())
}

/// An existing CA — its certificate and private key, PEM — under `ca_name`.
pub async fn import_ca(
    app: &AppContext,
    ca_name: &str,
    private_key: Vec<u8>,
    cert: Vec<u8>,
) -> Result<(), FlowError> {
    validate_name("caName", ca_name)?;
    let cert_pem = String::from_utf8(cert)
        .map_err(|e| FlowError::ValidationError(format!("Invalid certificate: {e}")))?;
    let key_pem = String::from_utf8(private_key)
        .map_err(|e| FlowError::ValidationError(format!("Invalid private key: {e}")))?;
    let key_pair = rcgen::KeyPair::from_pem(&key_pem)
        .map_err(|e| FlowError::ValidationError(format!("Invalid key pair: {e}")))?;
    rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair)
        .map_err(|e| FlowError::ValidationError(format!("Invalid CA certificate: {e}")))?;

    let mut opened = app.storage.lock().await?;
    let mut state = opened.state().clone();
    if state.cas.contains_key(ca_name) {
        return Err(FlowError::CaAlreadyGenerated);
    }
    state
        .cas
        .insert(ca_name.to_string(), CaModel::new(cert_pem, key_pem));
    opened
        .commit(state)
        .map_err(FlowError::SomethingWentWrong)?;
    let mut record = JournalRecord::of_ca(JournalEvent::CaImported, ca_name);
    record.by = Some("api".to_string());
    opened.journal(record);
    crate::log::info("A CA is imported");
    Ok(())
}

/// The private key of the CA, PEM. Journaled: whoever holds it can issue certificates.
pub async fn get_ca_private_key(app: &AppContext, ca_name: &str) -> Result<String, FlowError> {
    let opened = app.storage.lock().await?;
    let ca = opened
        .state()
        .cas
        .get(ca_name)
        .ok_or(FlowError::CaNotFound)?;
    let key = ca.private_key_pem.clone();
    opened.journal(JournalRecord::of_ca(JournalEvent::CaKeyDownloaded, ca_name));
    crate::log::warn("A CA private key is handed out");
    Ok(key)
}
