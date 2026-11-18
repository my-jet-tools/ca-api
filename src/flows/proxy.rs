//! What my-reverse-proxy reads — the CA certificate, and the serials of the revoked certificates
//! it refuses — always with the network key to encrypt it with. Without a network key nothing is
//! served: there is no way to the plain data.

use crate::app::AppContext;
use crate::crypto::envelope::{decode_key, Key};

use super::FlowError;

/// Data for my-reverse-proxy, and the key to encrypt it with.
pub struct ForProxy {
    pub content: String,
    pub network_key: Key,
}

/// The CA certificate, PEM.
pub async fn ca_cert_for_proxy(app: &AppContext, ca_name: &str) -> Result<ForProxy, FlowError> {
    let opened = app.storage.lock().await?;
    let network_key = network_key_of(opened.state().network_key.as_deref())?;
    let ca = opened
        .state()
        .cas
        .get(ca_name)
        .ok_or(FlowError::CaNotFound)?;
    Ok(ForProxy {
        content: ca.cert_pem.clone(),
        network_key,
    })
}

/// The serials of every certificate the CA revoked, as a YAML array, ascending: `[]` when none
/// is.
///
/// ```yaml
/// - 5
/// - 6
/// ```
pub async fn revoked_for_proxy(app: &AppContext, ca_name: &str) -> Result<ForProxy, FlowError> {
    let opened = app.storage.lock().await?;
    let network_key = network_key_of(opened.state().network_key.as_deref())?;
    let ca = opened
        .state()
        .cas
        .get(ca_name)
        .ok_or(FlowError::CaNotFound)?;
    let content = serde_yaml::to_string(&ca.revoked_serials())
        .map_err(|e| FlowError::SomethingWentWrong(format!("the revoked list: {e}")))?;
    Ok(ForProxy {
        content,
        network_key,
    })
}

fn network_key_of(network_key: Option<&str>) -> Result<Key, FlowError> {
    let network_key = network_key.ok_or(FlowError::NoNetworkKey)?;
    decode_key(network_key)
        .map_err(|e| FlowError::SomethingWentWrong(format!("the network key in the state: {e}")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_revoked_list_is_a_yaml_array_of_serials() {
        assert_eq!(serde_yaml::to_string(&[5u64, 6]).unwrap(), "- 5\n- 6\n");
        assert_eq!(serde_yaml::to_string(&Vec::<u64>::new()).unwrap(), "[]\n");
    }
}
