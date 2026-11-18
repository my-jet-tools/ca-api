use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_files_key};
use crate::storage::journal::JournalQuery;

#[http_route(
    method: "POST",
    route: "/api/journal",
    summary: "Read the journal",
    description: "What was done, newest first: {records, unreadable}. The body ({} for no filter) comes encrypted with the files key (aes128gcm); the answer is encrypted with it",
    controller: "Security",
    input_data: "GetJournalInputModel",
    result:[
        {status_code: 200, description: "The records, encrypted"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct GetJournalAction {
    app: Arc<AppContext>,
}

impl GetJournalAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &GetJournalAction,
    input_data: GetJournalInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_files_key(ctx)?;
    let query = JournalQuery {
        from: input_data.from,
        to: input_data.to,
        ca: input_data.ca_name,
        cn: input_data.cn,
        limit: input_data.limit.map(|limit| limit.min(usize::MAX as u64) as usize),
    };
    let page = crate::flows::read_journal(&action.app, &query).await?;
    encrypted(HttpOutput::as_json(page), &key)
}

#[derive(MyHttpInput)]
pub struct GetJournalInputModel {
    #[http_body(name = "from", description = "From this time on, unix seconds, included")]
    pub from: Option<u64>,

    #[http_body(name = "to", description = "Before this time, unix seconds, not included")]
    pub to: Option<u64>,

    #[http_body(name = "caName", description = "Only the records of this CA")]
    pub ca_name: Option<String>,

    #[http_body(name = "cn", description = "Only the records of this CN")]
    pub cn: Option<String>,

    #[http_body(name = "limit", description = "At most this many: 100 by default, 1000 at most")]
    pub limit: Option<u64>,
}
