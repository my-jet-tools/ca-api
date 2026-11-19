use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde_json::json;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_files_key};

#[http_route(
    method: "POST",
    route: "/api/delete-files-key-archive",
    summary: "Delete an archive of the data folder",
    description: "Delete the archive (YYYYMMDDhhmmss): there is no rolling back to it any more, and the files key of its time opens nothing on this disk. The body comes encrypted with the files key (aes128gcm); the answer {deleted} is encrypted with it",
    controller: "Security",
    input_data: "DeleteFilesKeyArchiveInputModel",
    result:[
        {status_code: 200, description: "Deleted, encrypted"},
        {status_code: 404, description: "No such archive"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct DeleteFilesKeyArchiveAction {
    app: Arc<AppContext>,
}

impl DeleteFilesKeyArchiveAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &DeleteFilesKeyArchiveAction,
    input_data: DeleteFilesKeyArchiveInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_files_key(ctx)?;
    crate::flows::delete_files_key_archive(&action.app, &input_data.archive).await?;
    encrypted(HttpOutput::as_json(json!({ "deleted": true })), &key)
}

#[derive(MyHttpInput)]
pub struct DeleteFilesKeyArchiveInputModel {
    #[http_body(name = "archive", description = "The archive, YYYYMMDDhhmmss")]
    pub archive: String,
}
