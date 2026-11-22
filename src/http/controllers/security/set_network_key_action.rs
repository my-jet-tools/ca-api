use std::sync::Arc;

use my_http_server::macros::*;
use my_http_server::*;
use serde_json::json;

use crate::app::AppContext;
use crate::flows::NetworkKeySet;
use crate::http::encryption::{encrypted, request_encryption_key};

#[http_route(
    method: "POST",
    route: "/api/set-network-key",
    summary: "Set the network key",
    description: "Keep the network key (base64 of 32 bytes) in the encrypted state. It opens every encrypted call but this one, change-key and rollback, and encrypts what my-reverse-proxy reads. Again with another key — a rotation: from the next request on only the new one is taken. Never returned. The body comes encrypted with the encryption key (aes128gcm); the answer {set, replaced, changed} is encrypted with it",
    controller: "Security",
    input_data: "SetNetworkKeyInputModel",
    result:[
        {status_code: 200, description: "Set, encrypted"},
        {status_code: 403, description: "Not base64 of 32 bytes, the encryption key itself, or a body under the network key"},
        {status_code: 415, description: "The body came in plain"},
    ]
)]
pub struct SetNetworkKeyAction {
    app: Arc<AppContext>,
}

impl SetNetworkKeyAction {
    pub fn new(app: Arc<AppContext>) -> Self {
        Self { app }
    }
}

async fn handle_request(
    action: &SetNetworkKeyAction,
    input_data: SetNetworkKeyInputModel,
    ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let key = request_encryption_key(&action.app, ctx)?;
    let result = crate::flows::set_network_key(&action.app, &input_data.network_key).await?;
    let response = json!({
        "set": true,
        "replaced": result == NetworkKeySet::Replaced,
        "changed": result != NetworkKeySet::Unchanged,
    });
    encrypted(HttpOutput::as_json(response), &key)
}

#[derive(MyHttpInput)]
pub struct SetNetworkKeyInputModel {
    #[http_body(name = "networkKey", description = "Base64 of 32 bytes: openssl rand -base64 32")]
    pub network_key: String,
}
