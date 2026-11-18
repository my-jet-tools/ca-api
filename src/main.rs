//! ca-api: a CA for client certificates — CAs, issuing and revoking, PKCS#12, and the list of
//! revoked certificates my-reverse-proxy refuses.
//!
//! Everything it knows is kept only encrypted, in the data folder, with a key that is never on the
//! disk: the service starts knowing nothing and is handed the key over its unix socket
//! (`POST /api/initialize`). Every call is encrypted — the management API with that key, what
//! my-reverse-proxy reads with the network key — so whoever gets into the machine can read and
//! change nothing: at most break it.

// `Result<HttpOkResult, HttpFailResult>` is my-http-server's own signature for every action.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use app::AppContext;
use my_settings_reader::SettingsReader;

use crate::settings::SettingsModel;

mod app;
mod crypto;
mod flows;
mod http;
mod log;
mod pem;
mod settings;
mod storage;

#[tokio::main]
async fn main() {
    let settings_reader: SettingsReader<SettingsModel> = SettingsReader::new("~/.ca-api");
    let settings = settings_reader.get_settings().await;
    let listen_mode = settings.get_http_listen_mode();

    let app = Arc::new(AppContext::new(&settings));

    crate::http::start(&app, listen_mode);
    app.app_states.wait_until_shutdown().await;
}
