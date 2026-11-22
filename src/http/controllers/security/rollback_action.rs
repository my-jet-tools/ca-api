use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde_json::json;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_encryption_key};

#[http_route(
    method: "POST",
    route: "/api/rollback",
    summary: "Roll the encryption key back to an archive",
    description: "Open an archive of the data folder — archive (YYYYMMDDhhmmss), or with none named the newest one — with key, the encryption key it was encrypted with. When the key fits, the archive is put back and key becomes the encryption key. What was in place is archived first, under its key, so a rollback is undone the same way. The body comes encrypted with the current encryption key (aes128gcm); the answer {rolled_back, restored, archive, network_key} is encrypted with it too — the key the call came with",
    controller: "Security",
    input_data: "RollbackInputModel",
    result:[
        {status_code: 200, description: "Rolled back, encrypted with the key the call came with"},
        {status_code: 403, description: "Not base64 of 32 bytes, the key opens no archive, or a body under the network key"},
        {status_code: 404, description: "No such archive"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct RollbackAction {
    app: Arc<AppContext>,
}

impl RollbackAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &RollbackAction,
    input_data: RollbackInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_encryption_key(&action.app, ctx)?;
    let done = crate::flows::roll_back_encryption_key(
        &action.app,
        &input_data.key,
        input_data.archive.as_deref(),
    )
    .await?;
    let response = json!({
        "rolled_back": true,
        "restored": done.restored,
        "archive": done.archive,
        "network_key": done.network_key,
    });
    encrypted(HttpOutput::as_json(response), &key)
}

#[derive(MyHttpInput)]
pub struct RollbackInputModel {
    #[http_body(
        name = "key",
        description = "The encryption key the archive was encrypted with, base64 of 32 bytes"
    )]
    pub key: String,

    #[http_body(
        name = "archive",
        description = "The archive, YYYYMMDDhhmmss: the newest one the key opens when not given"
    )]
    pub archive: Option<String>,
}
