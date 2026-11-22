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

    let encryption_text = encode_key(&generate_key().unwrap());
    let encryption = HttpBodyEncryptionKey::from_base64(&encryption_text).unwrap();
    let network_text = encode_key(&generate_key().unwrap());
    let network = HttpBodyEncryptionKey::from_base64(&network_text).unwrap();
    let stranger = HttpBodyEncryptionKey::from_base64(&encode_key(&generate_key().unwrap())).unwrap();

    // Locked: nothing is served.
    assert_eq!(get(t, "/api/ca/v1/downloadCert", "xfin-ca").await.status, 503);
    assert_eq!(get(t, "/api/revoked/v1/list", "xfin-ca").await.status, 503);
    assert_eq!(get(t, "/api/ca/v1/list", "").await.status, 409);
    assert_eq!(
        post_plain(s, "/api/is-initialized", json!({})).await.plain_json(),
        json!({ "initialized": false })
    );

    // The one plain call: the encryption key is taken over the unix socket only, and not from the
    // reverse proxy.
    let init = json!({ "key": encryption_text });
    assert_eq!(
        post_plain(t, "/api/initialize", init.clone()).await.status,
        403
    );
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

    // Until a network key is set, the calls it opens answer 409 — under the encryption key too.
    let issue = json!({ "caName": "xfin-ca", "email": "carol@example.com" });
    assert_eq!(get(t, "/api/ca/v1/list", "").await.status, 409);
    assert_eq!(
        post_encrypted(
            t,
            "/api/certificates/v1/generate",
            &encryption,
            issue.clone()
        )
        .await
        .status,
        409
    );
    // my-reverse-proxy's reads: nothing until a network key is set.
    assert_eq!(
        get(t, "/api/ca/v1/downloadCert", "xfin-ca").await.status,
        503
    );

    // The network key: set under the encryption key, and never the encryption key itself.
    let set_network = |key: &str| json!({ "networkKey": key });
    assert_eq!(
        post_plain(t, "/api/set-network-key", set_network(&network_text))
            .await
            .status,
        415
    );
    assert_eq!(
        post_encrypted(
            t,
            "/api/set-network-key",
            &stranger,
            set_network(&network_text)
        )
        .await
        .status,
        400
    );
    assert_eq!(
        post_encrypted(
            t,
            "/api/set-network-key",
            &encryption,
            set_network(&encryption_text)
        )
        .await
        .status,
        403
    );
    let set = post_encrypted(
        t,
        "/api/set-network-key",
        &encryption,
        set_network(&network_text),
    )
    .await;
    assert_eq!(
        set.json(&encryption),
        json!({ "set": true, "replaced": false, "changed": true })
    );
    // From now on it takes the encryption key alone: the network key opens it no more.
    assert_eq!(
        post_encrypted(
            t,
            "/api/set-network-key",
            &network,
            set_network(&network_text)
        )
        .await
        .status,
        403
    );

    // The lists: encrypted with the network key, over TCP too.
    let list = get(t, "/api/ca/v1/list", "").await;
    assert_eq!(list.status, 200);
    assert!(!String::from_utf8_lossy(&list.body).contains("xfin-ca"));
    assert!(encryption.decrypt(&list.body).is_err());
    assert_eq!(list.json(&network), json!(["xfin-ca"]));

    // A change needs a body encrypted with the network key: the encryption key opens it no more.
    assert_eq!(
        post_plain(t, "/api/certificates/v1/generate", issue.clone())
            .await
            .status,
        415
    );
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/generate", &stranger, issue.clone())
            .await
            .status,
        400
    );
    assert_eq!(
        post_encrypted(
            t,
            "/api/certificates/v1/generate",
            &encryption,
            issue.clone()
        )
        .await
        .status,
        403
    );
    let issued = post_encrypted(s, "/api/certificates/v1/generate", &network, issue.clone()).await;
    assert_eq!(issued.status, 200);
    // The legacy CA issued serials 1 and 5: the next id is 6.
    assert_eq!(
        issued.json(&network),
        json!({ "id": 6, "cn": "carol@example.com" })
    );
    assert_eq!(cert_state(t, &network, 6).await, Some(false));

    let ca = get(t, "/api/ca/v1/downloadCert", "xfin-ca").await;
    assert_eq!(ca.status, 200);
    assert_eq!(ca.content_type.as_deref(), Some("application/x-pem-file"));
    assert!(String::from_utf8(ca.open(&network))
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
    assert!(encryption.decrypt(&ca.body).is_err());
    assert_eq!(get(t, "/api/ca/v1/downloadCert", "nope").await.status, 404);

    // Revoking: encrypted, once. By email: every certificate of it that is not revoked.
    let revoke = json!({ "caName": "xfin-ca", "email": "carol@example.com" });
    assert_eq!(post_plain(t, "/api/certificates/v1/revoke", revoke.clone()).await.status, 415);
    let revoked = post_encrypted(t, "/api/certificates/v1/revoke", &network, revoke.clone()).await;
    assert_eq!(revoked.json(&network), json!({ "revoked": [6] }));
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &network, revoke).await.status,
        404
    );

    // Issuing the same email again adds certificates and replaces none: 6 stays revoked, in the CRL.
    for expected in [7, 8] {
        let again = post_encrypted(t, "/api/certificates/v1/generate", &network, issue.clone()).await;
        assert_eq!(again.json(&network)["id"], json!(expected));
    }
    assert_eq!(cert_state(t, &network, 6).await, Some(true));
    assert_eq!(cert_state(t, &network, 7).await, Some(false));
    // By id: that one only, once; with an email it must be that email's.
    let by_id = |id: u64| json!({ "caName": "xfin-ca", "id": id });
    let wrong_email = json!({ "caName": "xfin-ca", "id": 7, "email": "bob@example.com" });
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &network, wrong_email).await.status,
        404
    );
    let revoked = post_encrypted(t, "/api/certificates/v1/revoke", &network, by_id(7)).await;
    assert_eq!(revoked.json(&network), json!({ "revoked": [7] }));
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &network, by_id(7)).await.status,
        409
    );
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &network, by_id(99)).await.status,
        404
    );
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/revoke", &network, json!({ "caName": "xfin-ca" }))
            .await
            .status,
        403
    );
    assert_eq!(cert_state(t, &network, 8).await, Some(false));
    // What my-reverse-proxy refuses: a YAML array of the revoked serials, with the network key.
    let revoked_list = get(t, "/api/revoked/v1/list", "xfin-ca").await;
    assert_eq!(revoked_list.status, 200);
    assert_eq!(revoked_list.content_type.as_deref(), Some("application/yaml"));
    assert!(encryption.decrypt(&revoked_list.body).is_err());
    let yaml = String::from_utf8(revoked_list.open(&network)).unwrap();
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
        let p12 = post_encrypted(t, "/api/certificates/v1/downloadCert", &network, body).await;
        assert_eq!(p12.status, 200);
        assert_eq!(p12.content_type.as_deref(), Some("application/x-pkcs12"));
        assert!(p12.disposition.is_none());
        let parsed = openssl::pkcs12::Pkcs12::from_der(&p12.open(&network))
            .unwrap()
            .parse2("pw")
            .unwrap();
        assert!(parsed.pkey.is_some());
        let cert = parsed.cert.unwrap();
        assert_eq!(cert.serial_number().to_bn().unwrap().to_dec_str().unwrap().to_string(), serial.to_string());
    }
    let mismatch = json!({ "caName": "xfin-ca", "id": 6, "email": "bob@example.com", "password": "pw" });
    assert_eq!(
        post_encrypted(t, "/api/certificates/v1/downloadCert", &network, mismatch).await.status,
        404
    );

    let pk = post_encrypted(t, "/api/ca/v1/downloadPk", &network, json!({ "caName": "xfin-ca" })).await;
    assert!(String::from_utf8(pk.open(&network)).unwrap().contains("PRIVATE KEY"));

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
            .encrypted(&network)
            .post(HttpRequestBody::from(form))
            .await,
    )
    .await;
    assert!(imported.status < 300, "{}", imported.status);
    assert_eq!(
        get(t, "/api/ca/v1/list", "").await.json(&network),
        json!(["other-ca", "xfin-ca"])
    );

    // The journal: everything, encrypted.
    let journal = post_encrypted(t, "/api/journal", &network, json!({})).await.json(&network);
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
        &network,
        json!({ "cn": "carol@example.com", "limit": 2 }),
    )
    .await
    .json(&network);
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

#[tokio::test(flavor = "multi_thread")]
async fn the_encryption_key_is_changed_for_another_and_rolled_back() {
    let server = start().await;
    write_legacy_ca(&server.legacy.0, "xfin-ca");
    let (s, t) = (server.socket.as_str(), server.tcp.as_str());

    let key_pair = || {
        let text = encode_key(&generate_key().unwrap());
        let key = HttpBodyEncryptionKey::from_base64(&text).unwrap();
        (text, key)
    };
    let (old_text, old) = key_pair();
    let (new_text, new) = key_pair();
    let (network_text, network) = key_pair();
    let (_, stranger) = key_pair();

    assert_eq!(
        post_plain(s, "/api/initialize", json!({ "key": old_text }))
            .await
            .status,
        200
    );
    let set_network = json!({ "networkKey": network_text });
    let set = post_encrypted(t, "/api/set-network-key", &old, set_network.clone()).await;
    assert_eq!(set.status, 200);
    let issue = |email: &str| json!({ "caName": "xfin-ca", "email": email });
    assert_eq!(
        post_encrypted(
            t,
            "/api/certificates/v1/generate",
            &network,
            issue("carol@example.com")
        )
        .await
        .status,
        200
    );

    // The call: under the current encryption key — not the network key — and never to the
    // network key.
    let change = |key: &str| json!({ "newKey": key });
    let path = "/api/change-key";
    assert_eq!(post_plain(t, path, change(&new_text)).await.status, 415);
    assert_eq!(
        post_encrypted(t, path, &stranger, change(&new_text))
            .await
            .status,
        400
    );
    assert_eq!(
        post_encrypted(t, path, &network, change(&new_text))
            .await
            .status,
        403
    );
    assert_eq!(
        post_encrypted(t, path, &old, change("short")).await.status,
        403
    );
    assert_eq!(
        post_encrypted(t, path, &old, change(&network_text))
            .await
            .status,
        403
    );
    let same = post_encrypted(t, path, &old, change(&old_text))
        .await
        .json(&old);
    assert_eq!(same["changed"], json!(false));
    assert!(same["archive"].is_null());

    // The change: the answer under the key the call came with.
    let changed = post_encrypted(t, path, &old, change(&new_text)).await;
    assert_eq!(changed.status, 200);
    let changed = changed.json(&old);
    assert_eq!(changed["changed"], json!(true));
    let archive = changed["archive"].as_str().unwrap().to_string();
    assert!(
        archive.len() == 14 && archive.bytes().all(|b| b.is_ascii_digit()),
        "{archive}"
    );
    assert_eq!(changed["journal_unreadable"], json!(0));
    assert!(
        changed["journal_records"].as_u64().unwrap() >= 4,
        "{changed}"
    );

    // From now on the old encryption key opens nothing, the new one does; the network key is not
    // touched.
    assert_eq!(
        post_encrypted(t, "/api/set-network-key", &old, set_network.clone())
            .await
            .status,
        400
    );
    let again = post_encrypted(t, "/api/set-network-key", &new, set_network.clone()).await;
    assert_eq!(again.json(&new)["changed"], json!(false));
    assert_eq!(
        get(t, "/api/ca/v1/list", "").await.json(&network),
        json!(["xfin-ca"])
    );
    // The journal came along into the snapshot.
    let journal = post_encrypted(t, "/api/journal", &network, json!({}))
        .await
        .json(&network);
    assert_eq!(journal["unreadable"], json!(0));
    let records = journal["records"].as_array().unwrap();
    assert_eq!(records[0]["event"], json!("key_changed"));
    assert_eq!(records[0]["archive"], json!(archive));
    let events: Vec<&str> = records
        .iter()
        .map(|r| r["event"].as_str().unwrap())
        .collect();
    for event in [
        "initialized",
        "ca_imported",
        "cert_issued",
        "network_key_set",
    ] {
        assert!(events.contains(&event), "{event}: {events:?}");
    }
    assert!(String::from_utf8(
        get(t, "/api/ca/v1/downloadCert", "xfin-ca")
            .await
            .open(&network)
    )
    .unwrap()
    .contains("BEGIN CERTIFICATE"));

    // Done after the change: in the snapshot, not in the archive.
    post_encrypted(
        t,
        "/api/certificates/v1/generate",
        &network,
        issue("dave@example.com"),
    )
    .await;
    assert!(emails(t, &network)
        .await
        .contains(&"dave@example.com".to_string()));

    // The rollback: under the current encryption key. The archive is opened with the key the body
    // hands; when it fits, the archive is put back and that key is the encryption key.
    let rollback = "/api/rollback";
    let back = |key: &str| json!({ "key": key });
    assert_eq!(
        post_encrypted(t, rollback, &network, back(&old_text))
            .await
            .status,
        403
    );
    assert_eq!(
        post_encrypted(t, rollback, &new, back(&new_text))
            .await
            .status,
        403
    );
    assert_eq!(
        post_encrypted(
            t,
            rollback,
            &new,
            json!({ "key": old_text, "archive": "20000101000000" })
        )
        .await
        .status,
        404
    );
    let rolled_back = post_encrypted(
        t,
        rollback,
        &new,
        json!({ "key": old_text, "archive": archive }),
    )
    .await
    .json(&new);
    assert_eq!(rolled_back["restored"], json!(archive));
    assert_eq!(rolled_back["network_key"], json!(true));
    let replaced = rolled_back["archive"].as_str().unwrap().to_string();
    assert_ne!(replaced, archive);
    assert_eq!(
        post_encrypted(t, "/api/set-network-key", &new, set_network.clone())
            .await
            .status,
        400
    );
    let after_rollback = emails(t, &network).await;
    assert!(after_rollback.contains(&"carol@example.com".to_string()));
    assert!(!after_rollback.contains(&"dave@example.com".to_string()));

    // Undone the same way: with none named, the newest archive the key opens — what the rollback
    // replaced, under the new key.
    let undone = post_encrypted(t, rollback, &old, back(&new_text))
        .await
        .json(&old);
    assert_eq!(undone["restored"], json!(replaced));
    assert!(emails(t, &network)
        .await
        .contains(&"dave@example.com".to_string()));
    let journal = post_encrypted(t, "/api/journal", &network, json!({ "limit": 1 }))
        .await
        .json(&network);
    assert_eq!(journal["records"][0]["event"], json!("rolled_back"));
    assert_eq!(journal["records"][0]["restored"], json!(replaced));

    // On the disk, archives included: nothing readable.
    for entry in walk(&server.data.0) {
        let content = std::fs::read(&entry).unwrap();
        let text = String::from_utf8_lossy(&content);
        for secret in ["xfin-ca", "carol", "dave", "PRIVATE KEY", "CERTIFICATE"] {
            assert!(!text.contains(secret), "{entry} holds {secret}");
        }
    }
}

/// The CNs of every certificate of xfin-ca, as the list tells.
async fn emails(base: &str, key: &HttpBodyEncryptionKey) -> Vec<String> {
    get(base, "/api/certificates/v1/list", "xfin-ca")
        .await
        .json(key)
        .as_array()
        .unwrap()
        .iter()
        .map(|cert| cert["cn"].as_str().unwrap().to_string())
        .collect()
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
