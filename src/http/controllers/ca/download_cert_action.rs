use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::http::encryption::for_proxy;

#[http_route(
    method: "GET",
    route: "/api/ca/v1/downloadCert",
    summary: "Download CA certificate file",
    description: "The CA certificate as PEM, for my-reverse-proxy (client_certificate_ca[].ca): encrypted with the network key (Content-Encoding: aes128gcm, Content-Type: application/x-pem-file)",
    controller: "Certificate Authority",
    input_data: "DownloadCaCertInputModel",
    result:[
        {status_code: 200, description: "CA certificate as PEM, encrypted with the network key"},
        {status_code: 404, description: "No such CA"},
        {status_code: 503, description: "Not initialized yet, or no network key is set"},
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
    input_data: DownloadCaCertInputModel,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let ca = crate::flows::ca_cert_for_proxy(&action.app, &input_data.ca_name).await?;
    for_proxy(ca, "application/x-pem-file")
}

#[derive(MyHttpInput)]
struct DownloadCaCertInputModel {
    #[http_query(name = "caName", description = "CA Common Name")]
    pub ca_name: String,
}
