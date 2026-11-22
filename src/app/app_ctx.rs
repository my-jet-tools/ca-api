use std::sync::Arc;

use my_http_server::{BodyEncryptionKey, BodyEncryptionKeys};
use rust_extensions::AppStates;

use crate::settings::SettingsModel;
use crate::storage::{Opened, SecureStorage};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// The id of the encryption key — the one from `initialize`, which encrypts the data folder — in
/// [`AppContext::body_encryption_keys`]. It opens the calls that set the network key and change
/// the encryption key itself, and nothing else.
pub const ENCRYPTION_KEY_ID: &str = "encryption";
/// The id of the network key in [`AppContext::body_encryption_keys`]. It opens every other
/// encrypted call, and encrypts what my-reverse-proxy reads.
pub const NETWORK_KEY_ID: &str = "network";

pub struct AppContext {
    pub app_states: Arc<AppStates>,
    /// The CAs and everything else, encrypted; locked until `POST /api/initialize`.
    pub storage: SecureStorage,
    /// The keys my-http-server opens a `Content-Encoding: aes128gcm` request body with, and with
    /// them the salts it has accepted, so no body is accepted twice. Empty until `initialize`;
    /// then the encryption key under [`ENCRYPTION_KEY_ID`] and, once there is one, the network
    /// key under [`NETWORK_KEY_ID`]. Every server of the process is handed this one `Arc`.
    pub body_encryption_keys: Arc<BodyEncryptionKeys>,
}

impl AppContext {
    pub fn new(settings: &SettingsModel) -> Self {
        let storage = SecureStorage::new(settings.get_data_folder(), settings.get_legacy_pki());
        Self {
            app_states: Arc::new(AppStates::create_initialized()),
            storage,
            body_encryption_keys: Arc::new(BodyEncryptionKeys::default()),
        }
    }

    /// Hand my-http-server the keys `opened` has now: from the next request on, a call is opened
    /// with them alone. Called under the lock of the state after every change of either key —
    /// `initialize`, a rollback, a change of the encryption key, a network key set.
    pub fn refresh_call_keys(&self, opened: &Opened) {
        let keys = [
            (ENCRYPTION_KEY_ID, Some(*opened.encryption_key())),
            (NETWORK_KEY_ID, opened.network_key()),
        ];
        let keys = keys
            .into_iter()
            .filter_map(|(id, key)| BodyEncryptionKey::from_bytes(id, &key?).ok())
            .collect();
        self.body_encryption_keys.set(keys);
    }
}
