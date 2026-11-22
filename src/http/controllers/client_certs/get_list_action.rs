use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde::*;

use crate::app::AppContext;
use crate::flows::IssuedCertificateInfo;
use crate::http::encryption::{encrypted, network_key};

#[http_route(
    method: "GET",
    route: "/api/certificates/v1/list",
    summary: "Get list of certificates",
    description: "Every certificate the CA issued, revoked ones included, as JSON [{id, cn, revoked, issued_at, revoked_at}] encrypted with the network key (aes128gcm). The id is the serial; an email may have several certificates",
    controller: "Client Certificates",
    input_data: "GetListInputModel",
    result:[
        {status_code: 200, description: "List of issued certificates, encrypted"},
    ]
)]
pub struct GetListOfCertificatesAction {
    app: Arc<AppContext>,
}

impl GetListOfCertificatesAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &GetListOfCertificatesAction,
    input_data: GetListInputModel,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = network_key(&action.app)?;
    let result =
        crate::flows::list_issued_certificates(&action.app, &input_data.ca_name).await?;
    let response: Vec<IssuedCertificateHttpModel> = result.into_iter().map(|x| x.into()).collect();
    encrypted(HttpOutput::as_json(response), &key)
}

#[derive(MyHttpInput)]
struct GetListInputModel {
    #[http_query(name = "caName", description = "CA Common Name")]
    pub ca_name: String,
}

#[derive(MyHttpInputObjectStructure, Serialize, Deserialize)]
struct IssuedCertificateHttpModel {
    /// The serial: the certificate's id within its CA.
    pub id: u64,
    pub cn: String,
    pub revoked: bool,
    /// unix seconds
    pub issued_at: i64,
    /// unix seconds
    pub revoked_at: Option<i64>,
}

impl From<IssuedCertificateInfo> for IssuedCertificateHttpModel {
    fn from(value: IssuedCertificateInfo) -> Self {
        Self {
            id: value.id,
            cn: value.cn,
            revoked: value.revoked_at.is_some(),
            issued_at: value.issued_at,
            revoked_at: value.revoked_at,
        }
    }
}
