use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde_json::json;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_encryption_key};

#[http_route(
    method: "POST",
    route: "/api/change-key",
    summary: "Change the encryption key",
    description: "Change the encryption key for another one (base64 of 32 bytes), handed in the body. The data folder as it is goes to archive/<YYYYMMDDhhmmss>, still under the old key, and a snapshot of it under the new key — the state and the journal — takes its place. From then on only the new key opens the folder and the calls it opens. The body comes encrypted with the current encryption key (aes128gcm); the answer {changed, archive, journal_records, journal_unreadable} is encrypted with it too — the key the call came with",
    controller: "Security",
    input_data: "ChangeKeyInputModel",
    result:[
        {status_code: 200, description: "Changed, encrypted with the key the call came with"},
        {status_code: 403, description: "Not base64 of 32 bytes, the network key, or a body under the network key"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct ChangeKeyAction {
    app: Arc<AppContext>,
}

impl ChangeKeyAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &ChangeKeyAction,
    input_data: ChangeKeyInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_encryption_key(&action.app, ctx)?;
    let done = crate::flows::change_encryption_key(&action.app, &input_data.new_key).await?;
    let response = json!({
        "changed": done.changed,
        "archive": done.archive,
        "journal_records": done.journal_records,
        "journal_unreadable": done.journal_unreadable,
    });
    encrypted(HttpOutput::as_json(response), &key)
}

#[derive(MyHttpInput)]
pub struct ChangeKeyInputModel {
    #[http_body(
        name = "newKey",
        description = "The new encryption key, base64 of 32 bytes: openssl rand -base64 32"
    )]
    pub new_key: String,
}
