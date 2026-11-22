use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;

use crate::app::AppContext;
use crate::flows::PemCertInfo;
use crate::http::encryption::request_network_key;

#[http_route(
    method: "POST",
    route: "/api/ca/v1/generate",
    summary: "Generate new CA",
    description: "Generate new CA. The body comes encrypted with the network key (aes128gcm)",
    controller: "Certificate Authority",
    input_data: "GenerateCaInputModel",
    result:[
        {status_code: 202, description: "CA is generated"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct GenerateCaAction {
    app: Arc<AppContext>,
}

impl GenerateCaAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &GenerateCaAction,
    input_data: GenerateCaInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    request_network_key(&action.app, ctx)?;
    crate::flows::generate_ca(
        &action.app,
        PemCertInfo {
            ca_cn: input_data.ca_name,
            organization: input_data.organization,
            country_code: input_data.country_code,
            city: input_data.city,
        },
    )
    .await?;

    HttpOutput::Empty.into_ok_result(true)
}

#[derive(MyHttpInput)]
pub struct GenerateCaInputModel {
    #[http_body(name = "caName", description = "Common name")]
    pub ca_name: String,

    #[http_body(name = "organization", description = "Organization")]
    pub organization: String,

    #[http_body(name = "countryCode", description = "Country Code ISO 3166-1 alpha-2")]
    pub country_code: String,

    #[http_body(name = "city", description = "City")]
    pub city: String,
}
