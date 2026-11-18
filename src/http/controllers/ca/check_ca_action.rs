use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_files_key};

#[http_route(
    method: "POST",
    route: "/api/ca/v1/check",
    summary: "Check CA exists",
    description: "Check CA exists. The body comes encrypted with the files key (aes128gcm); the answer is encrypted with it",
    controller: "Certificate Authority",
    input_data: "CheckCaCertificateInputModel",
    result:[
        {status_code: 200, description: "CA is present"},
        {status_code: 404, description: "No such CA"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct CheckCaAction {
    app: Arc<AppContext>,
}

impl CheckCaAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &CheckCaAction,
    input_data: CheckCaCertificateInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_files_key(ctx)?;
    crate::flows::check_ca(&action.app, &input_data.ca_name).await?;
    encrypted(HttpOutput::as_text("Ok".to_string()), &key)
}

#[derive(MyHttpInput)]
pub struct CheckCaCertificateInputModel {
    #[http_body(name = "caName", description = "CA Common Name")]
    pub ca_name: String,
}
