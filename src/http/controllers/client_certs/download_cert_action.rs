use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::flows::CertSelector;
use crate::http::encryption::{encrypted, request_network_key};

#[http_route(
    method: "POST",
    route: "/api/certificates/v1/downloadCert",
    summary: "Download client certificate as PKCS#12",
    description: "The certificate `id` — or, with `email` alone, the newest certificate of the email that is not revoked — with its private key and the CA as PKCS#12, protected by the password. The body comes encrypted with the network key (aes128gcm); the answer is encrypted with it. Journaled",
    controller: "Client Certificates",
    input_data: "DownloadClientCertInputModel",
    result:[
        {status_code: 200, description: "PKCS#12 binary (application/x-pkcs12), encrypted"},
        {status_code: 404, description: "No such CA or certificate"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct DownloadCertAction {
    app: Arc<AppContext>,
}

impl DownloadCertAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &DownloadCertAction,
    input_data: DownloadClientCertInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_network_key(&action.app, ctx)?;
    let (selector, email) = CertSelector::of(input_data.id, input_data.email)?;
    let (_, p12) = crate::flows::get_p12(
        &action.app,
        &input_data.ca_name,
        &selector,
        email.as_deref(),
        &input_data.password,
    )
    .await?;

    // No file name in a header: headers are not encrypted, and it would be the email.
    let builder = HttpResultBuilder::new()
        .set_status_code(200)
        .set_content(p12)
        .set_content_type(WebContentType::Raw("application/x-pkcs12".to_string()));
    encrypted(builder, &key)
}

#[derive(MyHttpInput)]
struct DownloadClientCertInputModel {
    #[http_body(name = "caName", description = "CA Common Name")]
    pub ca_name: String,

    #[http_body(name = "id", description = "The certificate's id (its serial)")]
    pub id: Option<u64>,

    #[http_body(name = "email", description = "Without id: the newest certificate of this email that is not revoked. With id: the certificate must be this email's")]
    pub email: Option<String>,

    #[http_body(name = "password", description = "Certificate Password")]
    pub password: String,
}
