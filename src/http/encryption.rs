//! What every call is encrypted with.
//!
//! - The management API — with the files key (the key the service was initialized with). A call
//!   that reads or changes something comes as a `POST` whose body is encrypted with it
//!   (`Content-Encoding: aes128gcm`): my-http-server opens it and refuses a replay before the
//!   action runs, so a body proves its sender holds the key. A plain body is refused with `415`.
//!   The answer is encrypted with the same key. The lists come as `GET`: the request proves
//!   nothing, and the answer is useless without the key.
//! - What my-reverse-proxy reads (the CA certificate, the list of revoked serials) — with the
//!   network key from the state. Without one, `503`: there is no way to the plain data.
//!
//! Refusals and errors carry no data and stay plain.

use my_http_server::{
    BodyEncryptionKey, HttpBodyEncryptionKey, HttpContext, HttpFailResult, HttpOkResult,
    HttpResultBuilder, WebContentType,
};

use crate::app::{AppContext, FILES_KEY_ID};
use crate::flows::ForProxy;

/// The files key the request body came encrypted with. `415` for a plain body.
pub fn request_files_key(ctx: &HttpContext) -> Result<BodyEncryptionKey, HttpFailResult> {
    match ctx.request.get_encryption_info() {
        Some(info) if info.key.get_id() == FILES_KEY_ID => Ok(info.key.clone()),
        Some(_) => Err(HttpFailResult::from((
            403u16,
            "only the files key opens this call",
        ))),
        None => Err(HttpFailResult::from((
            415u16,
            "the body has to come encrypted with the files key: Content-Encoding: aes128gcm",
        ))),
    }
}

/// The files key, to encrypt the answer to a `GET` with. `409` before `initialize`.
pub fn files_key(app: &AppContext) -> Result<BodyEncryptionKey, HttpFailResult> {
    app.body_encryption_keys
        .get_by_id(FILES_KEY_ID)
        .ok_or_else(|| HttpFailResult::from((409u16, "the service is not initialized")))
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
