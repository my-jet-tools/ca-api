use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, files_key};

#[http_route(
    method: "GET",
    route: "/api/files-key-archives",
    summary: "List the archives of the data folder",
    description: "The archives the files key changes and rollbacks left, newest first: [\"YYYYMMDDhhmmss\", …], as JSON encrypted with the files key (aes128gcm). Each one opens only with the files key of its time",
    controller: "Security",
    result:[
        {status_code: 200, description: "The archive ids, encrypted"},
    ]
)]
pub struct FilesKeyArchivesAction {
    app: Arc<AppContext>,
}

impl FilesKeyArchivesAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &FilesKeyArchivesAction,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = files_key(&action.app)?;
    let archives = crate::flows::files_key_archives(&action.app).await?;
    encrypted(HttpOutput::as_json(archives), &key)
}
