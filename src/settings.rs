use serde::{Deserialize, Serialize};

use crate::storage::ca::CaDataPath;

#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsModel {
    pub config_path: String,
    pub unix_socket: Option<String>,
    pub unix_socket_only: Option<bool>,
}

pub enum HttpListenMode {
    Tcp,
    TcpAndUnixSocket(String),
    UnixSocketOnly(String),
}

impl SettingsModel {
    pub fn get_http_listen_mode(&self) -> HttpListenMode {
        let unix_socket_only = self.unix_socket_only.unwrap_or(false);

        let Some(unix_socket) = self.unix_socket.as_deref() else {
            if unix_socket_only {
                panic!("Settings: unix_socket_only is true, but unix_socket is not set");
            }
            return HttpListenMode::Tcp;
        };

        let unix_socket = rust_extensions::file_utils::format_path(unix_socket).to_string();

        if unix_socket_only {
            HttpListenMode::UnixSocketOnly(unix_socket)
        } else {
            HttpListenMode::TcpAndUnixSocket(unix_socket)
        }
    }

    pub fn get_config_path(&self) -> ConfigPath {
        let mut path =
            rust_extensions::file_utils::format_path(self.config_path.as_str()).to_string();

        if path.ends_with(std::path::MAIN_SEPARATOR) {
            path.pop();
        }

        ConfigPath { path }
    }
}

pub struct ConfigPath {
    path: String,
}

impl ConfigPath {
    pub fn as_str(&self) -> &str {
        self.path.as_str()
    }

    pub fn into_ca_data_path(self, ca_cn: &str) -> CaDataPath {
        CaDataPath::new(self.path, ca_cn)
    }
}
