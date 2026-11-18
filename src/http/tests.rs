//! The API end to end, as a client and my-reverse-proxy see it: real servers on a unix socket and
//! a TCP port, FlUrl with encrypted bodies.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use flurl::body::{FormDataBody, HttpRequestBody};
use flurl::my_http_utils::HttpBodyEncryptionKey;
use flurl::FlUrl;
use my_http_server::MyHttpServer;
use serde_json::{json, Value};

use super::start_up::{start_server, HttpMiddlewares};
use crate::app::AppContext;
use crate::crypto::envelope::{encode_key, generate_key};
use crate::settings::SettingsModel;
use crate::storage::data_folder::tests::{temp_folder, Folder};
use crate::storage::legacy::tests::write_legacy_ca;

struct TestServer {
    socket: String,
    tcp: String,
    data: Folder,
    legacy: Folder,
    _socket_file: Folder,
}

async fn start() -> TestServer {
    let data = Folder::new();
    let legacy = Folder::new();
    let socket = Folder(format!("{}.sock", temp_folder()));
    let settings = SettingsModel {
        data_folder: data.0.clone(),
        config_path: Some(legacy.0.clone()),
        unix_socket: Some(socket.0.clone()),
        unix_socket_only: Some(false),
    };
    let app = Arc::new(AppContext::new(&settings));
    let middlewares = HttpMiddlewares::new(&app);

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let tcp = MyHttpServer::new(SocketAddr::from(([127, 0, 0, 1], port)));
    start_server(tcp, false, &app, &middlewares);
    start_server(
        MyHttpServer::new_as_unix_socket(socket.0.clone()),
        true,
        &app,
        &middlewares,
    );
    for _ in 0..100 {
        if std::path::Path::new(&socket.0).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    TestServer {
        socket: format!("http+unix://{}", socket.0),
        tcp: format!("http://127.0.0.1:{port}"),
        data,
        legacy,
        _socket_file: socket,
    }
}

/// What came back: the status, `Content-Encoding`, `Content-Type`, `Content-Disposition`, the body
/// as it came.
struct Answer {
    status: u16,
    encoding: Option<String>,
    content_type: Option<String>,
    disposition: Option<String>,
    body: Vec<u8>,
}

impl Answer {
    fn is_encrypted(&self) -> bool {
        self.encoding.as_deref() == Some("aes128gcm")
    }

    fn open(&self, key: &HttpBodyEncryptionKey) -> Vec<u8> {
        assert!(self.is_encrypted(), "a plain answer: {}", self.status);
        key.decrypt(&self.body).expect("the answer opens with the key")
    }

    fn json(&self, key: &HttpBodyEncryptionKey) -> Value {
        serde_json::from_slice(&self.open(key)).unwrap()
    }

    fn plain_json(&self) -> Value {
        assert!(!self.is_encrypted());
        serde_json::from_slice(&self.body).unwrap()
    }
}

fn url(base: &str, path: &str) -> FlUrl {
    let mut url = FlUrl::new(base);
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        url = url.append_path_segment(segment);
    }
    url
}

async fn read(response: Result<flurl::FlUrlResponse, flurl::FlUrlError>) -> Answer {
    let mut response = response.unwrap();
    let header = |name: &str| {
        response
            .get_header_case_insensitive(name)
            .ok()
            .flatten()
            .map(str::to_string)
    };
    let (encoding, content_type, disposition) = (
        header("content-encoding"),
        header("content-type"),
        header("content-disposition"),
    );
    let status = response.get_status_code();
    let body = response
        .get_body()
        .unwrap()
        .into_vec(16 * 1024 * 1024)
        .await
        .unwrap();
    Answer {
        status,
        encoding,
        content_type,
        disposition,
        body,
    }
}

async fn get(base: &str, path: &str, ca_name: &str) -> Answer {
    read(url(base, path).append_query_param("caName", Some(ca_name)).get().await).await
}

async fn post_plain(base: &str, path: &str, body: Value) -> Answer {
    read(url(base, path).post(HttpRequestBody::as_json(&body)).await).await
}

async fn post_encrypted(base: &str, path: &str, key: &HttpBodyEncryptionKey, body: Value) -> Answer {
    read(
        url(base, path)
            .encrypted(key)
            .post(HttpRequestBody::as_json(&body))
            .await,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn whoever_has_no_key_reads_nothing_and_changes_nothing() {
    let server = start().await;
    write_legacy_ca(&server.legacy.0, "xfin-ca");
    let (s, t) = (server.socket.as_str(), server.tcp.as_str());

    let files_key_text = encode_key(&generate_key().unwrap());
    let files_key = HttpBodyEncryptionKey::from_base64(&files_key_text).unwrap();
    let network_key_text = encode_key(&generate_key().unwrap());
    let network_key = HttpBodyEncryptionKey::from_base64(&network_key_text).unwrap();
    let stranger = HttpBodyEncryptionKey::from_base64(&encode_key(&generate_key().unwrap())).unwrap();

    // Locked: nothing is served.
    assert_eq!(get(t, "/api/ca/v1/downloadCert", "xfin-ca").await.status, 503);
    assert_eq!(get(t, "/api/revoked/v1/list", "xfin-ca").await.status, 503);
    assert_eq!(get(t, "/api/ca/v1/list", "").await.status, 409);
    assert_eq!(
        post_plain(s, "/api/is-initialized", json!({})).await.plain_json(),
        json!({ "initialized": false })
    );

    // The key is taken over the unix socket only, and not from the reverse proxy.
    let init = json!({ "key": files_key_text });
    assert_eq!(post_plain(t, "/api/initialize", init.clone()).await.status, 403);
    let relayed = url(s, "/api/initialize")
        .with_header("X-Forwarded-For", "203.0.113.7")
        .post(HttpRequestBody::as_json(&init))
        .await;
    assert_eq!(read(relayed).await.status, 403);

    let answer = post_plain(s, "/api/initialize", init.clone()).await;
    assert_eq!(answer.status, 200);
    let done = answer.plain_json();
    assert_eq!(done["created"], json!(true));
    assert_eq!(done["imported"], json!({ "cas": 1, "certificates": 2 }));
    assert_eq!(done["network_key"], json!(false));
    assert_eq!(done["legacy_plaintext_left"], json!(true));
    assert!(done.get("key").is_none());
    assert_eq!(post_plain(s, "/api/initialize", init).await.status, 409);

    // The lists: encrypted with the files key, over TCP too.
    let list = get(t, "/api/ca/v1/list", "").await;
    assert_eq!(list.status, 200);
    assert!(!String::from_utf8_lossy(&list.body).contains("xfin-ca"));
    assert_eq!(list.json(&files_key), json!(["xfin-ca"]));

    // A change needs a body encrypted with the files key.
    let issue = json!({ "caName": "xfin-ca", "email": "carol@example.com" });
    assert_eq!(post_plain(t, "/api/certificates/v1/generate", issue.clone()).await.status, 415);
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/generate", &stranger, issue.clone()).await.status,
        400
    );
    let issued = post_encrypted(s, "/api/certificates/v1/generate", &files_key, issue.clone()).await;
    assert_eq!(issued.status, 200);
    // The legacy CA issued serials 1 and 5: the next id is 6.
    assert_eq!(issued.json(&files_key), json!({ "id": 6, "cn": "carol@example.com" }));
    assert_eq!(cert_state(t, &files_key, 6).await, Some(false));

    // my-reverse-proxy's reads: nothing until a network key is set — never the files key.
    assert_eq!(get(t, "/api/ca/v1/downloadCert", "xfin-ca").await.status, 503);
    let refused = post_encrypted(
        t,
        "/api/set-network-key",
        &files_key,
        json!({ "networkKey": files_key_text }),
    )
    .await;
    assert_eq!(refused.status, 403);
    let set = post_encrypted(
        t,
        "/api/set-network-key",
        &files_key,
        json!({ "networkKey": network_key_text }),
    )
    .await;
    assert_eq!(
        set.json(&files_key),
        json!({ "set": true, "replaced": false, "changed": true })
    );

    let ca = get(t, "/api/ca/v1/downloadCert", "xfin-ca").await;
    assert_eq!(ca.status, 200);
    assert_eq!(ca.content_type.as_deref(), Some("application/x-pem-file"));
    assert!(String::from_utf8(ca.open(&network_key))
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
    assert!(files_key.decrypt(&ca.body).is_err());
    assert_eq!(get(t, "/api/ca/v1/downloadCert", "nope").await.status, 404);

    // Revoking: encrypted, once. By email: every certificate of it that is not revoked.
    let revoke = json!({ "caName": "xfin-ca", "email": "carol@example.com" });
    assert_eq!(post_plain(t, "/api/certificates/v1/revoke", revoke.clone()).await.status, 415);
    let revoked = post_encrypted(t, "/api/certificates/v1/revoke", &files_key, revoke.clone()).await;
    assert_eq!(revoked.json(&files_key), json!({ "revoked": [6] }));
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &files_key, revoke).await.status,
        404
    );

    // Issuing the same email again adds certificates and replaces none: 6 stays revoked, in the CRL.
    for expected in [7, 8] {
        let again = post_encrypted(t, "/api/certificates/v1/generate", &files_key, issue.clone()).await;
        assert_eq!(again.json(&files_key)["id"], json!(expected));
    }
    assert_eq!(cert_state(t, &files_key, 6).await, Some(true));
    assert_eq!(cert_state(t, &files_key, 7).await, Some(false));
    // By id: that one only, once; with an email it must be that email's.
    let by_id = |id: u64| json!({ "caName": "xfin-ca", "id": id });
    let wrong_email = json!({ "caName": "xfin-ca", "id": 7, "email": "bob@example.com" });
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &files_key, wrong_email).await.status,
        404
    );
    let revoked = post_encrypted(t, "/api/certificates/v1/revoke", &files_key, by_id(7)).await;
    assert_eq!(revoked.json(&files_key), json!({ "revoked": [7] }));
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &files_key, by_id(7)).await.status,
        409
    );
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &files_key, by_id(99)).await.status,
        404
    );
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &files_key, json!({ "caName": "xfin-ca" }))
            .await
            .status,
        403
    );
    assert_eq!(cert_state(t, &files_key, 8).await, Some(false));
    // What my-reverse-proxy refuses: a YAML array of the revoked serials, with the network key.
    let revoked_list = get(t, "/api/revoked/v1/list", "xfin-ca").await;
    assert_eq!(revoked_list.status, 200);
    assert_eq!(revoked_list.content_type.as_deref(), Some("application/yaml"));
    assert!(files_key.decrypt(&revoked_list.body).is_err());
    let yaml = String::from_utf8(revoked_list.open(&network_key)).unwrap();
    // bob's 5, revoked before the import, and carol's 6 and 7.
    assert_eq!(yaml, "- 5\n- 6\n- 7\n");
    assert_eq!(serde_yaml::from_str::<Vec<u64>>(&yaml).unwrap(), [5, 6, 7]);
    assert_eq!(get(t, "/api/revoked/v1/list", "nope").await.status, 404);
    // No CRL any more.
    for path in ["/api/revoked/v1/crl", "/api/ca/v1/downloadRevokedPem"] {
        assert_eq!(get(t, path, "xfin-ca").await.status, 404, "{path}");
    }

    // PKCS#12: the password in the encrypted body, the answer encrypted, no name in a header. By
    // email: the newest certificate of it that is not revoked; by id: that one.
    for (body, serial) in [
        (json!({ "caName": "xfin-ca", "email": "carol@example.com", "password": "pw" }), 8u32),
        (json!({ "caName": "xfin-ca", "id": 6, "password": "pw" }), 6),
    ] {
        let p12 = post_encrypted(t, "/api/certificates/v1/downloadCert", &files_key, body).await;
        assert_eq!(p12.status, 200);
        assert_eq!(p12.content_type.as_deref(), Some("application/x-pkcs12"));
        assert!(p12.disposition.is_none());
        let parsed = openssl::pkcs12::Pkcs12::from_der(&p12.open(&files_key))
            .unwrap()
            .parse2("pw")
            .unwrap();
        assert!(parsed.pkey.is_some());
        let cert = parsed.cert.unwrap();
        assert_eq!(cert.serial_number().to_bn().unwrap().to_dec_str().unwrap().to_string(), serial.to_string());
    }
    let mismatch = json!({ "caName": "xfin-ca", "id": 6, "email": "bob@example.com", "password": "pw" });
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/downloadCert", &files_key, mismatch).await.status,
        404
    );

    let pk = post_encrypted(t, "/api/ca/v1/downloadPk", &files_key, json!({ "caName": "xfin-ca" })).await;
    assert!(String::from_utf8(pk.open(&files_key)).unwrap().contains("PRIVATE KEY"));

    // Import: the multipart body, encrypted.
    let other = crate::crypto::build_ca(&crate::pem::PemCertInfo {
        ca_cn: "other".to_string(),
        organization: String::new(),
        country_code: String::new(),
        city: String::new(),
    })
    .unwrap();
    let form = FormDataBody::new("ca-api-test")
        .append_form_data_field("caName", "other-ca")
        .append_form_data_file("cert", "ca.pem", "", other.cert_pem.as_bytes())
        .append_form_data_file("privateKey", "key.pem", "", other.key_pem.as_bytes());
    let imported = read(
        url(t, "/api/ca/v1/import")
            .encrypted(&files_key)
            .post(HttpRequestBody::from(form))
            .await,
    )
    .await;
    assert!(imported.status < 300, "{}", imported.status);
    assert_eq!(
        get(t, "/api/ca/v1/list", "").await.json(&files_key),
        json!(["other-ca", "xfin-ca"])
    );

    // The journal: everything, encrypted.
    let journal = post_encrypted(t, "/api/journal", &files_key, json!({})).await.json(&files_key);
    let events: Vec<&str> = journal["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    for event in [
        "initialized",
        "ca_imported",
        "cert_issued",
        "network_key_set",
        "cert_revoked",
        "pfx_downloaded",
        "ca_key_downloaded",
    ] {
        assert!(events.contains(&event), "{event}: {events:?}");
    }
    let of_carol = post_encrypted(
        t,
        "/api/journal",
        &files_key,
        json!({ "cn": "carol@example.com", "limit": 2 }),
    )
    .await
    .json(&files_key);
    assert_eq!(of_carol["records"].as_array().unwrap().len(), 2);
    let revocations = journal["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|record| record["event"] == "cert_revoked")
        .map(|record| record["serial"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(revocations, [7, 6]);

    // On the disk: nothing readable.
    for entry in walk(&server.data.0) {
        let content = std::fs::read(&entry).unwrap();
        let text = String::from_utf8_lossy(&content);
        for secret in ["xfin-ca", "carol", "PRIVATE KEY", "CERTIFICATE"] {
            assert!(!text.contains(secret), "{entry} holds {secret}");
        }
    }
}

/// Whether the certificate `id` of xfin-ca is revoked, as the list tells; `None` when it is not
/// there.
async fn cert_state(base: &str, key: &HttpBodyEncryptionKey, id: u64) -> Option<bool> {
    let list = get(base, "/api/certificates/v1/list", "xfin-ca").await.json(key);
    list.as_array()
        .unwrap()
        .iter()
        .find(|cert| cert["id"] == json!(id))
        .map(|cert| {
            assert_eq!(cert["revoked"].as_bool().unwrap(), !cert["revoked_at"].is_null());
            cert["revoked"].as_bool().unwrap()
        })
}

fn walk(root: &str) -> Vec<String> {
    let mut files = Vec::new();
    let mut dirs = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.push(path.to_string_lossy().to_string());
            }
        }
    }
    files
}
