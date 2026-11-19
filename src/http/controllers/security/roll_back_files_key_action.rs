use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde_json::json;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_files_key};

#[http_route(
    method: "POST",
    route: "/api/rollback-files-key",
    summary: "Roll the files key back to an archive",
    description: "Put an archive of the data folder back — archive (YYYYMMDDhhmmss), or the newest one — with key, the files key it is encrypted with, as the files key from then on. What it replaces is archived first, so a rollback is undone the same way. Everything done since that archive is in the archive of what was replaced. The body comes encrypted with the current files key (aes128gcm); the answer {rolled_back, restored, archive} is encrypted with it too — the key the call came with",
    controller: "Security",
    input_data: "RollBackFilesKeyInputModel",
    result:[
        {status_code: 200, description: "Rolled back, encrypted with the key the call came with"},
        {status_code: 403, description: "Not base64 of 32 bytes, or not the key of the archive"},
        {status_code: 404, description: "No such archive, or none at all"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct RollBackFilesKeyAction {
    app: Arc<AppContext>,
}

impl RollBackFilesKeyAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &RollBackFilesKeyAction,
    input_data: RollBackFilesKeyInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_files_key(ctx)?;
    let done = crate::flows::roll_back_files_key(
        &action.app,
        &input_data.key,
        input_data.archive.as_deref(),
    )
    .await?;
    let response = json!({
        "rolled_back": true,
        "restored": done.restored,
        "archive": done.archive,
    });
    encrypted(HttpOutput::as_json(response), &key)
}

#[derive(MyHttpInput)]
pub struct RollBackFilesKeyInputModel {
    #[http_body(
        name = "key",
        description = "The files key the archive is encrypted with, base64 of 32 bytes"
    )]
    pub key: String,

    #[http_body(
        name = "archive",
        description = "The archive, YYYYMMDDhhmmss: the newest one when not given"
    )]
    pub archive: Option<String>,
}
