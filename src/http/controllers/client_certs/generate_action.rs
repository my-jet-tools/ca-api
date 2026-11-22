use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde_json::json;

use crate::app::AppContext;
use crate::http::encryption::{encrypted, request_network_key};

#[http_route(
    method: "POST",
    route: "/api/certificates/v1/generate",
    summary: "Generate Client Certificate",
    description: "Issue a client certificate (CN = email, RSA-4096, 10 years) — always a new one under a new id: the certificates the email has stay as they are. The body comes encrypted with the network key (aes128gcm); the answer {id, cn} is encrypted with it",
    controller: "Client Certificates",
    input_data: "GenerateCertificateInputModel",
    result:[
        {status_code: 200, description: "The id of the new certificate, encrypted"},
        {status_code: 404, description: "No such CA"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct GenerateCertificateAction {
    app: Arc<AppContext>,
}

impl GenerateCertificateAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &GenerateCertificateAction,
    input_data: GenerateCertificateInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_network_key(&action.app, ctx)?;
    let id = crate::flows::generate_cert(&action.app, &input_data.ca_name, &input_data.email).await?;
    encrypted(
        HttpOutput::as_json(json!({ "id": id, "cn": input_data.email })),
        &key,
    )
}

#[derive(MyHttpInput)]
pub struct GenerateCertificateInputModel {
    #[http_body(name = "caName", description = "CA Common Name")]
    pub ca_name: String,

    #[http_body(name = "email", description = "Email")]
    pub email: String,
}
