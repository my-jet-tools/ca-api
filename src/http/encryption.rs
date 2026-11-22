//! What every call is encrypted with.
//!
//! - `POST /api/initialize` is the one plain call: it hands the encryption key over, inside only.
//! - The **encryption key** (from `initialize`, it encrypts the data folder) opens only
//!   `/api/set-network-key`, `/api/change-key` and `/api/rollback`.
//! - The **network key** (set with `/api/set-network-key`, kept in the state) opens every other
//!   call, and encrypts what my-reverse-proxy reads.
//!
//! A call that reads or changes something comes as a `POST` whose body is encrypted with its key
//! (`Content-Encoding: aes128gcm`): my-http-server opens it and refuses a replay before the action
//! runs, so a body proves its sender holds the key. A body under the other key is refused with
//! `403`, a plain one with `415`; before a network key is set, a call it opens answers `409`. The
//! answer is encrypted with the key the call came with. The lists come as `GET`: the request
//! proves nothing, and the answer, under the network key, is useless without it.
//!
//! Refusals and errors carry no data and stay plain.

use my_http_server::{
    BodyEncryptionKey, HttpBodyEncryptionKey, HttpContext, HttpFailResult, HttpOkResult,
    HttpResultBuilder, WebContentType,
};

use crate::app::{AppContext, ENCRYPTION_KEY_ID, NETWORK_KEY_ID};
use crate::flows::ForProxy;

/// The key a call is opened with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKey {
    /// Setting the network key, changing the encryption key, rolling it back.
    Encryption,
    /// Everything else.
    Network,
}

impl CallKey {
    /// Its id in [`AppContext::body_encryption_keys`].
    pub fn id(self) -> &'static str {
        match self {
            Self::Encryption => ENCRYPTION_KEY_ID,
            Self::Network => NETWORK_KEY_ID,
        }
    }
}

/// The encryption key the request body came under, for setting the network key, changing the
/// encryption key and rolling it back.
pub fn request_encryption_key(
    app: &AppContext,
    ctx: &HttpContext,
) -> Result<BodyEncryptionKey, HttpFailResult> {
    request_key(app, ctx, CallKey::Encryption)
}

/// The network key the request body came under, for every other call.
pub fn request_network_key(
    app: &AppContext,
    ctx: &HttpContext,
) -> Result<BodyEncryptionKey, HttpFailResult> {
    request_key(app, ctx, CallKey::Network)
}

fn request_key(
    app: &AppContext,
    ctx: &HttpContext,
    wanted: CallKey,
) -> Result<BodyEncryptionKey, HttpFailResult> {
    if wanted == CallKey::Network {
        no_network_key_yet(app)?;
    }
    match ctx.request.get_encryption_info() {
        Some(info) if info.key.get_id() == wanted.id() => Ok(info.key.clone()),
        Some(_) => Err(HttpFailResult::from((
            403u16,
            format!("this call takes the {} key", wanted.id()),
        ))),
        None => Err(HttpFailResult::from((
            415u16,
            format!(
                "the body has to come encrypted with the {} key: Content-Encoding: aes128gcm",
                wanted.id()
            ),
        ))),
    }
}

/// The network key, to encrypt the answer to a `GET` with. `409` while there is none.
pub fn network_key(app: &AppContext) -> Result<BodyEncryptionKey, HttpFailResult> {
    app.body_encryption_keys
        .get_by_id(NETWORK_KEY_ID)
        .ok_or_else(no_network_key)
}

fn no_network_key_yet(app: &AppContext) -> Result<(), HttpFailResult> {
    match app.body_encryption_keys.get_by_id(NETWORK_KEY_ID) {
        Some(_) => Ok(()),
        None => Err(no_network_key()),
    }
}

fn no_network_key() -> HttpFailResult {
    HttpFailResult::from((
        409u16,
        "there is no network key yet: set it with /api/set-network-key, under the encryption key",
    ))
}

/// `builder`'s body encrypted with `key`: `Content-Encoding: aes128gcm`, `Cache-Control:
/// no-store`.
pub fn encrypted(
    builder: HttpResultBuilder,
    key: &HttpBodyEncryptionKey,
) -> Result<HttpOkResult, HttpFailResult> {
    builder.encode(key).into_ok_result(true)
}

/// Data for my-reverse-proxy, encrypted with the network key. `content_type` is the type of the
/// data once decrypted.
pub fn for_proxy(data: ForProxy, content_type: &str) -> Result<HttpOkResult, HttpFailResult> {
    let key = HttpBodyEncryptionKey::from_bytes(&data.network_key)
        .map_err(|e| HttpFailResult::as_fatal_error(e.to_string()))?;
    let builder = HttpResultBuilder::new()
        .set_status_code(200)
        .set_content(data.content.into_bytes())
        .set_content_type(WebContentType::Raw(content_type.to_string()));
    encrypted(builder, &key)
}
