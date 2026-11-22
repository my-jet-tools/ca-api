use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_network_key};

#[http_route(
    method: "POST",
    route: "/api/ca/v1/downloadPk",
    summary: "Download CA private key",
    description: "The CA private key as PEM. The body comes encrypted with the network key (aes128gcm); the answer is encrypted with it. Journaled",
    controller: "Certificate Authority",
    input_data: "DownloadCaPrivateKeyInputModel",
    result:[
        {status_code: 200, description: "CA private key as PEM, encrypted"},
        {status_code: 404, description: "No such CA"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct DownloadPrivateKeyAction {
    app: Arc<AppContext>,
}

impl DownloadPrivateKeyAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &DownloadPrivateKeyAction,
    input_data: DownloadCaPrivateKeyInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_network_key(&action.app, ctx)?;
    let pem = crate::flows::get_ca_private_key(&action.app, &input_data.ca_name).await?;
    encrypted(HttpOutput::as_text(pem), &key)
}

#[derive(MyHttpInput)]
struct DownloadCaPrivateKeyInputModel {
    #[http_body(name = "caName", description = "CA Common Name")]
    pub ca_name: String,
}
