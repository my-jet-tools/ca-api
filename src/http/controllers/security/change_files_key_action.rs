use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde_json::json;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_files_key};

#[http_route(
    method: "POST",
    route: "/api/change-files-key",
    summary: "Change the files key",
    description: "Change the files key for another one (base64 of 32 bytes). The data folder as it is goes to archive/<YYYYMMDDhhmmss>, still encrypted with the old key, and a snapshot of it encrypted with the new key — the state and the journal — takes its place. From then on only the new key opens the folder and the calls. The body comes encrypted with the current files key (aes128gcm); the answer {changed, archive, journal_records, journal_unreadable} is encrypted with it too — the key the call came with",
    controller: "Security",
    input_data: "ChangeFilesKeyInputModel",
    result:[
        {status_code: 200, description: "Changed, encrypted with the key the call came with"},
        {status_code: 403, description: "Not base64 of 32 bytes, or the network key"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct ChangeFilesKeyAction {
    app: Arc<AppContext>,
}

impl ChangeFilesKeyAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &ChangeFilesKeyAction,
    input_data: ChangeFilesKeyInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_files_key(ctx)?;
    let done = crate::flows::change_files_key(&action.app, &input_data.new_key).await?;
    let response = json!({
        "changed": done.changed,
        "archive": done.archive,
        "journal_records": done.journal_records,
        "journal_unreadable": done.journal_unreadable,
    });
    encrypted(HttpOutput::as_json(response), &key)
}

#[derive(MyHttpInput)]
pub struct ChangeFilesKeyInputModel {
    #[http_body(
        name = "newKey",
        description = "The new files key, base64 of 32 bytes: openssl rand -base64 32"
    )]
    pub new_key: String,
}
