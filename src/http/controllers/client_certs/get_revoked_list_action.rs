use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::http::encryption::for_proxy;

#[http_route(
    method: "GET",
    route: "/api/revoked/v1/list",
    summary: "Get List of revoked certificates",
    description: "For my-reverse-proxy, which refuses these certificates: the serials of every certificate the CA revoked, as a YAML array ([] when none), encrypted with the network key (Content-Encoding: aes128gcm, Content-Type: application/yaml)",
    controller: "Client Certificates",
    input_data: "GetRevokedCertsInputModel",
    result:[
        {status_code: 200, description: "The revoked serials as YAML, encrypted with the network key"},
        {status_code: 404, description: "No such CA"},
        {status_code: 503, description: "Not initialized yet, or no network key is set"},
    ]
)]
pub struct GetListOfRevokedCertificatesAction {
    app: Arc<AppContext>,
}

impl GetListOfRevokedCertificatesAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &GetListOfRevokedCertificatesAction,
    input_data: GetRevokedCertsInputModel,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let revoked = crate::flows::revoked_for_proxy(&action.app, &input_data.ca_name).await?;
    for_proxy(revoked, "application/yaml")
}

#[derive(MyHttpInput)]
struct GetRevokedCertsInputModel {
    #[http_query(name = "caName", description = "CA Common Name")]
    pub ca_name: String,
}
