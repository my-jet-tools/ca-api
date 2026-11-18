//! In front of every route:
//!
//! - `POST /api/initialize` `{"key"?}` — hands the service its key, once per start. The key goes
//!   in plain text, so it is taken over the unix socket only, and never from a request the reverse
//!   proxy relayed (`X-Forwarded-For`): `403` otherwise.
//! - `GET|POST /api/is-initialized` → `{"initialized"}`.
//! - Until the service has its key, every other `/api/…` call is answered here: `503` for what
//!   my-reverse-proxy reads (so it keeps what it read last), `409` for the rest.

use std::sync::Arc;

use my_http_server::hyper::Method;
use my_http_server::{
    BodyEncryptionKey, HttpContext, HttpFailResult, HttpOkResult, HttpOutput,
    HttpResponseHeaders, HttpServerMiddleware, WebContentType,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::app::{AppContext, FILES_KEY_ID};
use crate::storage::InitializeError;

/// The routes my-reverse-proxy reads, lower case.
const PROXY_ROUTES: [&str; 2] = ["/api/ca/v1/downloadcert", "/api/revoked/v1/list"];

pub struct GateMiddleware {
    app: Arc<AppContext>,
    /// Whether this is the server of the unix socket — the only one the key is taken on.
    over_unix_socket: bool,
}

impl GateMiddleware {
    pub fn new(app: Arc<AppContext>, over_unix_socket: bool) -> Self {
        Self {
            app,
            over_unix_socket,
        }
    }
}

#[derive(Default, Deserialize)]
struct InitializeBody {
    /// The key, base64 of 32 bytes. None — only for a data folder with no state yet: the service
    /// makes one.
    #[serde(default)]
    key: Option<String>,
}

#[async_trait::async_trait]
impl HttpServerMiddleware for GateMiddleware {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
    ) -> Option<Result<HttpOkResult, HttpFailResult>> {
        let path = ctx.request.get_path().as_str().to_ascii_lowercase();
        let route = path.trim_end_matches('/');
        let method = ctx.request.method.clone();

        if route == "/api/initialize" && method == Method::POST {
            return Some(Ok(self.initialize(ctx).await));
        }
        if route == "/api/is-initialized" && (method == Method::POST || method == Method::GET) {
            let initialized = self.app.storage.is_initialized();
            return Some(Ok(json_response(200, json!({ "initialized": initialized }))));
        }
        if !route.starts_with("/api/") || self.app.storage.is_initialized() {
            return None;
        }
        let response = if PROXY_ROUTES.contains(&route) {
            json_response(
                503,
                json!({ "error": "the service is not initialized: it waits for its key" }),
            )
        } else {
            json_response(
                409,
                json!({ "error": "the service is not initialized: it waits for its key (POST /api/initialize over the unix socket)" }),
            )
        };
        Some(Ok(response))
    }
}

impl GateMiddleware {
    async fn initialize(&self, ctx: &mut HttpContext) -> HttpOkResult {
        if !self.over_unix_socket {
            crate::log::warn("/api/initialize refused: it came over TCP");
            return json_response(
                403,
                json!({ "error": "the key is taken over the unix socket only" }),
            );
        }
        if ctx.request.data.headers().contains_key("x-forwarded-for") {
            crate::log::warn("/api/initialize refused: a request relayed by the reverse proxy");
            return json_response(
                403,
                json!({ "error": "not available through the reverse proxy" }),
            );
        }
        let body = match ctx.request.get_body().await {
            Ok(body) => body.as_slice().to_vec(),
            Err(_) => {
                return json_response(400, json!({ "error": "the request body cannot be read" }))
            }
        };
        let body: InitializeBody = if body.iter().all(u8::is_ascii_whitespace) {
            InitializeBody::default()
        } else {
            match serde_json::from_slice(&body) {
                Ok(body) => body,
                Err(_) => {
                    return json_response(
                        400,
                        json!({ "error": "invalid body: expected {\"key\": \"<base64 of 32 bytes>\"}" }),
                    )
                }
            }
        };

        let (done, key) = match self.app.storage.initialize(body.key.as_deref()).await {
            Ok(done) => done,
            Err(e @ InitializeError::AlreadyInitialized) => {
                crate::log::warn(format!("/api/initialize refused: {e}"));
                return json_response(409, json!({ "error": e.to_string() }));
            }
            Err(e @ InitializeError::WrongKey) => {
                crate::log::warn(format!("/api/initialize refused: {e}"));
                return json_response(403, json!({ "error": e.to_string() }));
            }
            Err(e @ InitializeError::BadKey(_)) => {
                crate::log::warn(format!("/api/initialize refused: {e}"));
                return json_response(400, json!({ "error": e.to_string() }));
            }
            Err(e @ InitializeError::Failed(_)) => {
                crate::log::warn(format!("The service is not initialized: {e}"));
                return json_response(500, json!({ "error": e.to_string() }));
            }
        };

        // From now on my-http-server opens the bodies of the encrypted calls with the files key.
        match BodyEncryptionKey::from_bytes(FILES_KEY_ID, &key) {
            Ok(key) => self.app.body_encryption_keys.set(vec![key]),
            Err(e) => crate::log::warn(format!("The encrypted calls stay closed: {e}")),
        }

        let how = if done.created {
            "the data folder is created"
        } else {
            "the key opened the data folder"
        };
        crate::log::info(format!("The service is initialized: {how}"));
        if let Some((cas, certificates)) = done.imported {
            crate::log::info(format!(
                "The plaintext PKI folder is imported: {cas} CA(s), {certificates} certificate record(s)"
            ));
        }
        if !done.deleted.is_empty() {
            crate::log::info(format!(
                "Deleted from the data folder, as not encrypted: {} path(s)",
                done.deleted.len()
            ));
        }
        let legacy_plaintext_left = self.app.storage.legacy_plaintext_left();
        if legacy_plaintext_left {
            crate::log::warn(
                "The plaintext PKI folder (config_path) is still on the disk, and its keys are readable there: delete it once the import is checked",
            );
        }

        let mut response = json!({
            "initialized": true,
            "created": done.created,
            "cas": done.cas,
            "certificates": done.certificates,
            "network_key": done.network_key,
            "deleted": done.deleted,
            "legacy_plaintext_left": legacy_plaintext_left,
        });
        if let Some((cas, certificates)) = done.imported {
            response["imported"] = json!({ "cas": cas, "certificates": certificates });
        }
        if let Some(key) = done.generated_key {
            response["key"] = Value::from(key);
        }
        json_response(200, response)
    }
}

fn json_response(status: u16, body: Value) -> HttpOkResult {
    HttpOutput::Content {
        status_code: status,
        headers: HttpResponseHeaders::new(Some(WebContentType::Json)),
        content: body.to_string().into_bytes(),
    }
    .as_ok(false)
}
