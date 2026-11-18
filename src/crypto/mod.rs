mod build_ca;
mod build_client_cert;
mod build_p12;

pub use build_ca::*;
pub use build_client_cert::*;
pub use build_p12::*;
pub mod envelope;

/// The CA that signs, from its certificate and private key (PEM).
pub fn build_issuer(
    cert_pem: &str,
    key_pem: &str,
) -> Result<rcgen::Issuer<'static, rcgen::KeyPair>, String> {
    let key_pair = rcgen::KeyPair::from_pem(key_pem).map_err(|e| e.to_string())?;
    rcgen::Issuer::from_ca_cert_pem(cert_pem, key_pair).map_err(|e| e.to_string())
}
