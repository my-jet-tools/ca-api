use std::{net::SocketAddr, sync::Arc};

use my_http_server::controllers::swagger::SwaggerMiddleware;
use my_http_server::controllers::ControllersMiddleware;
use my_http_server::MyHttpServer;

use crate::app::AppContext;
use crate::settings::HttpListenMode;

const HTTP_TCP_PORT: u16 = 8000;

pub fn start(app: &Arc<AppContext>) {
    let controllers = Arc::new(super::builder::build_controllers(app));

    let swagger_middleware = Arc::new(SwaggerMiddleware::new(
        controllers.clone(),
        crate::app::APP_NAME.to_string(),
        crate::app::APP_VERSION.to_string(),
    ));

    let middlewares = HttpMiddlewares {
        swagger: swagger_middleware,
        controllers,
    };

    match app.settings.get_http_listen_mode() {
        HttpListenMode::Tcp => {
            start_server(create_tcp_server(), app, &middlewares);
        }
        HttpListenMode::TcpAndUnixSocket(unix_socket) => {
            start_server(create_tcp_server(), app, &middlewares);
            start_server(
                MyHttpServer::new_as_unix_socket(unix_socket),
                app,
                &middlewares,
            );
        }
        HttpListenMode::UnixSocketOnly(unix_socket) => {
            start_server(
                MyHttpServer::new_as_unix_socket(unix_socket),
                app,
                &middlewares,
            );
        }
    }
}

struct HttpMiddlewares {
    swagger: Arc<SwaggerMiddleware>,
    controllers: Arc<ControllersMiddleware>,
}

fn create_tcp_server() -> MyHttpServer {
    MyHttpServer::new(SocketAddr::from(([0, 0, 0, 0], HTTP_TCP_PORT)))
}

fn start_server(
    mut http_server: MyHttpServer,
    app: &Arc<AppContext>,
    middlewares: &HttpMiddlewares,
) {
    http_server.add_middleware(middlewares.swagger.clone());
    http_server.add_middleware(middlewares.controllers.clone());
    http_server.start(app.app_states.clone(), my_logger::LOGGER.clone());
}
