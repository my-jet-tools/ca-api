use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde_json::json;

use crate::app::AppContext;
use crate::flows::CertSelector;
use crate::http::encryption::{encrypted, request_network_key};

#[http_route(
    method: "POST",
    route: "/api/certificates/v1/revoke",
    summary: "Revoke certificate",
    description: "Revoke the certificate `id` — or, with `email` alone, every certificate of the email that is not revoked — and rebuild the CRL. The body comes encrypted with the network key (aes128gcm); the answer {revoked: [ids]} is encrypted with it",
    controller: "Client Certificates",
    input_data: "RevokeClientCertInputModel",
    result:[
        {status_code: 200, description: "The ids revoked, encrypted"},
        {status_code: 404, description: "No such CA, or no such certificate"},
        {status_code: 409, description: "The certificate is revoked already"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct RevokeCertificateAction {
    app: Arc<AppContext>,
}

impl RevokeCertificateAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &RevokeCertificateAction,
    input_data: RevokeClientCertInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_network_key(&action.app, ctx)?;
    let (selector, email) = CertSelector::of(input_data.id, input_data.email)?;
    let revoked = crate::flows::revoke_cert(
        &action.app,
        &input_data.ca_name,
        &selector,
        email.as_deref(),
    )
    .await?;
    encrypted(HttpOutput::as_json(json!({ "revoked": revoked })), &key)
}

#[derive(MyHttpInput)]
struct RevokeClientCertInputModel {
    #[http_body(name = "caName", description = "CA Common Name")]
    pub ca_name: String,

    #[http_body(name = "id", description = "The certificate's id (its serial)")]
    pub id: Option<u64>,

    #[http_body(name = "email", description = "Without id: every certificate of this email that is not revoked. With id: the certificate must be this email's")]
    pub email: Option<String>,
}
