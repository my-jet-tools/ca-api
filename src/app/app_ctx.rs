use std::sync::Arc;

use my_http_server::BodyEncryptionKeys;
use rust_extensions::AppStates;

use crate::settings::SettingsModel;
use crate::storage::SecureStorage;

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// The id of the files key in [`AppContext::body_encryption_keys`].
pub const FILES_KEY_ID: &str = "files";

pub struct AppContext {
    pub app_states: Arc<AppStates>,
    /// The CAs and everything else, encrypted; locked until `POST /api/initialize`.
    pub storage: SecureStorage,
    /// The keys my-http-server opens a `Content-Encoding: aes128gcm` request body with, and with
    /// them the salts it has accepted, so no body is accepted twice. Empty until `initialize`; then
    /// the files key alone, under [`FILES_KEY_ID`] — never the network key, which my-reverse-proxy
    /// holds. Every server of the process is handed this one `Arc`.
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
}
