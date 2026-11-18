use std::path::Path;

use serde::{Deserialize, Serialize};

/// `~/.ca-api`. Nothing secret is here: the CAs, the keys and the network key are only in the
/// encrypted state.
#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsModel {
    /// The folder ca-api keeps everything in — the state and the journal, encrypted with the key
    /// it is handed (`POST /api/initialize`). It belongs to the service alone: anything else in it
    /// is deleted once the key is handed. `~` is expanded. Required.
    #[serde(alias = "data-folder")]
    pub data_folder: String,
    /// The plaintext PKI folder of ca-api 0.2. Read once, when the first key creates the state,
    /// and never changed: delete it once the import is checked. Must not overlap `data_folder`.
    #[serde(default, alias = "config-path")]
    pub config_path: Option<String>,
    /// The unix socket the API is served on — the only way to hand the service its key. `~` is
    /// expanded. Required.
    #[serde(default, alias = "unix-socket")]
    pub unix_socket: Option<String>,
    /// `true` — serve on the unix socket only; TCP port 8000 is not opened.
    #[serde(default, alias = "unix-socket-only")]
    pub unix_socket_only: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpListenMode {
    TcpAndUnixSocket(String),
    UnixSocketOnly(String),
}

impl SettingsModel {
    /// Panics without `unix_socket`: the key is handed over it, and without it the service could
    /// never be initialized.
    pub fn get_http_listen_mode(&self) -> HttpListenMode {
        let Some(unix_socket) = non_empty(self.unix_socket.as_deref()) else {
            panic!("Settings: unix_socket is required: the key is handed over it (POST /api/initialize)");
        };
        let unix_socket = rust_extensions::file_utils::format_path(unix_socket).to_string();
        if self.unix_socket_only.unwrap_or(false) {
            HttpListenMode::UnixSocketOnly(unix_socket)
        } else {
            HttpListenMode::TcpAndUnixSocket(unix_socket)
        }
    }

    /// Panics when it is not set.
    pub fn get_data_folder(&self) -> String {
        let Some(folder) = non_empty(Some(self.data_folder.as_str())) else {
            panic!("Settings: data_folder is empty");
        };
        format_folder(folder)
    }

    /// The plaintext folder of 0.2 to import from. Panics when it overlaps the data folder: the
    /// data folder is swept of everything that is not encrypted.
    pub fn get_legacy_pki(&self) -> Option<String> {
        let legacy = format_folder(non_empty(self.config_path.as_deref())?);
        let data_folder = self.get_data_folder();
        if Path::new(&data_folder).starts_with(&legacy) || Path::new(&legacy).starts_with(&data_folder)
        {
            panic!(
                "Settings: data_folder must be a folder of its own, apart from config_path: \
                 everything in it that is not encrypted is deleted"
            );
        }
        Some(legacy)
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn format_folder(folder: &str) -> String {
    let mut path = rust_extensions::file_utils::format_path(folder).to_string();
    while path.len() > 1 && path.ends_with(std::path::MAIN_SEPARATOR) {
        path.pop();
    }
    path
}

#[cfg(test)]
mod tests {
    use super::{HttpListenMode, SettingsModel};

    const REQUIRED: &str = "data-folder: /root/data\nunix-socket: /sock/ca-api.http-sock\n";

    fn parse(extra: &str) -> SettingsModel {
        serde_yaml::from_str(&format!("{REQUIRED}{extra}")).unwrap()
    }

    #[test]
    fn listen_modes() {
        assert_eq!(
            parse("").get_http_listen_mode(),
            HttpListenMode::TcpAndUnixSocket("/sock/ca-api.http-sock".to_string())
        );
        assert_eq!(
            parse("unix_socket_only: true\n").get_http_listen_mode(),
            HttpListenMode::UnixSocketOnly("/sock/ca-api.http-sock".to_string())
        );
    }

    #[test]
    #[should_panic(expected = "unix_socket is required")]
    fn without_a_socket_the_service_does_not_start() {
        let settings: SettingsModel = serde_yaml::from_str("data_folder: /root/data\n").unwrap();
        settings.get_http_listen_mode();
    }

    #[test]
    fn settings_of_0_2_without_a_data_folder_are_refused() {
        assert!(serde_yaml::from_str::<SettingsModel>("config_path: /root/pki\n").is_err());
    }

    #[test]
    fn folders() {
        assert_eq!(parse("").get_data_folder(), "/root/data");
        assert_eq!(parse("").get_legacy_pki(), None);
        assert_eq!(
            parse("config_path: /root/pki/\n").get_legacy_pki().as_deref(),
            Some("/root/pki")
        );
        // A sibling whose name starts the same is apart.
        let settings: SettingsModel =
            serde_yaml::from_str("data_folder: /root/pki2\nconfig_path: /root/pki\n").unwrap();
        assert_eq!(settings.get_legacy_pki().as_deref(), Some("/root/pki"));
    }

    #[test]
    fn the_data_folder_never_overlaps_the_plaintext_folder() {
        for (data, legacy) in [
            ("/root/pki", "/root/pki"),
            ("/root/pki/data", "/root/pki"),
            ("/root", "/root/pki"),
        ] {
            let yaml = format!("data_folder: {data}\nconfig_path: {legacy}\n");
            let settings: SettingsModel = serde_yaml::from_str(&yaml).unwrap();
            let result = std::panic::catch_unwind(|| settings.get_legacy_pki());
            assert!(result.is_err(), "{data} / {legacy}");
        }
    }
}
