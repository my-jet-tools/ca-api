use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, network_key};

#[http_route(
    method: "GET",
    route: "/api/ca/v1/list",
    summary: "Get list of CA",
    description: "The names of the CAs, as JSON encrypted with the network key (aes128gcm)",
    controller: "Certificate Authority",
    result:[
        {status_code: 200, description: "The CA names, encrypted"},
    ]
)]
pub struct GetListOfCaAction {
    app: Arc<AppContext>,
}

impl GetListOfCaAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &GetListOfCaAction,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = network_key(&action.app)?;
    let result = crate::flows::list_cas(&action.app).await?;
    encrypted(HttpOutput::as_json(result), &key)
}
