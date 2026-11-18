use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::http::encryption::request_files_key;

#[http_route(
    method: "POST",
    route: "/api/ca/v1/import",
    summary: "Import existing CA",
    description: "Import existing CA. The multipart body comes encrypted with the files key (aes128gcm)",
    controller: "Certificate Authority",
    input_data: "ImportCaInputModel",
    result:[
        {status_code: 202, description: "CA is imported"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct ImportCaAction {
    app: Arc<AppContext>,
}

impl ImportCaAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &ImportCaAction,
    input_data: ImportCaInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    request_files_key(ctx)?;
    crate::flows::import_ca(
        &action.app,
        &input_data.ca_name,
        input_data.private_key.into_vec(),
        input_data.cert.into_vec(),
    )
    .await?;

    HttpOutput::Empty.into_ok_result(true)
}

#[derive(MyHttpInput)]
pub struct ImportCaInputModel {
    #[http_form_data(name = "caName", description = "CA Common Name")]
    pub ca_name: String,

    #[http_form_data(description = "Certificate")]
    pub cert: RawData,

    #[http_form_data(name = "privateKey", description = "Private key")]
    pub private_key: RawData,
}
