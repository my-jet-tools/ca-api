use std::{net::SocketAddr, sync::Arc};

use my_http_server::controllers::swagger::SwaggerMiddleware;
use my_http_server::controllers::ControllersMiddleware;
use my_http_server::MyHttpServer;

use super::gate::GateMiddleware;
use crate::app::AppContext;
use crate::settings::HttpListenMode;

const HTTP_TCP_PORT: u16 = 8000;

pub fn start(app: &Arc<AppContext>, listen_mode: HttpListenMode) {
    let middlewares = HttpMiddlewares::new(app);

    let unix_socket = match listen_mode {
        HttpListenMode::TcpAndUnixSocket(unix_socket) => {
            let tcp = MyHttpServer::new(SocketAddr::from(([0, 0, 0, 0], HTTP_TCP_PORT)));
            start_server(tcp, false, app, &middlewares);
            unix_socket
        }
        HttpListenMode::UnixSocketOnly(unix_socket) => unix_socket,
    };
    start_server(
        MyHttpServer::new_as_unix_socket(unix_socket),
        true,
        app,
        &middlewares,
    );
}

pub(super) struct HttpMiddlewares {
    swagger: Arc<SwaggerMiddleware>,
    controllers: Arc<ControllersMiddleware>,
}

impl HttpMiddlewares {
    pub(super) fn new(app: &Arc<AppContext>) -> Self {
        let controllers = Arc::new(super::builder::build_controllers(app));
        let swagger = Arc::new(SwaggerMiddleware::new(
            controllers.clone(),
            crate::app::APP_NAME.to_string(),
            crate::app::APP_VERSION.to_string(),
        ));
        Self {
            swagger,
            controllers,
        }
    }
}

/// `over_unix_socket` — whether `http_server` is the unix socket's: the only one the key is taken
/// on.
pub(super) fn start_server(
    mut http_server: MyHttpServer,
    over_unix_socket: bool,
    app: &Arc<AppContext>,
    middlewares: &HttpMiddlewares,
) {
    // Every server shares the keys, and with them the salts already accepted.
    http_server.set_body_encryption_keys(app.body_encryption_keys.clone());
    http_server.add_middleware(Arc::new(GateMiddleware::new(app.clone(), over_unix_socket)));
    http_server.add_middleware(middlewares.swagger.clone());
    http_server.add_middleware(middlewares.controllers.clone());
    http_server.start(app.app_states.clone(), my_logger::LOGGER.clone());
}
