# ca-api

A CA for client certificates over HTTP: CA roots, issuing and revoking client certificates, PKCS#12 bundles, and the list of revoked certificates my-reverse-proxy refuses. There is no CRL. Pure Rust (`rcgen` + `openssl` FFI), no `easy-rsa` or `openssl` CLI at runtime.

**Everything is encrypted.** The aim: whoever gets into the machine — its disk, its unix sockets, the container network — can neither read anything (CA names, emails, certificates, private keys) nor change anything (issue, revoke, import). At most they can break the service.

- On the disk there is only encrypted data: `state.enc` and the journal, AES-256-GCM.
- The key that encrypts them is never on the disk. It lives in the service's memory, from `initialize` until the process ends. After every start the service knows nothing until it is handed the key over its unix socket.
- Every call is encrypted. The management API uses that key (the **files key**). What my-reverse-proxy reads uses the **network key**, which is kept in the encrypted state. A request without the right key is refused before anything runs. A captured request cannot be sent again.
- The log tells only what happened ("A client certificate is issued"), never about which CA or whom. Those details are only in the encrypted journal.


## Settings

`~/.ca-api` (YAML):

```yaml
data_folder: /root/data                                  # required: the encrypted state and journal
unix_socket: /root/system-sockets/ca-api.http-sock       # required: the key is handed over it
unix_socket_only: true                                   # optional, default false: no TCP port 8000
config_path: /root/pki                                   # optional: the plaintext folder of 0.2, to import once
```

Keys can also be written in kebab case (`data-folder`, `unix-socket`, …). `~` is expanded.

| Field | Meaning |
|---|---|
| `data_folder` | The folder the service keeps everything in, encrypted. **It belongs to the service alone:** once the key opens it, everything in it except `state.enc` and `journal/<yyyy-mm>.log` is deleted. |
| `unix_socket` | The socket the API is served on. Required, since `POST /api/initialize` is taken only here. A stale socket file is removed on start. |
| `unix_socket_only` | `false` (the default): also TCP `0.0.0.0:8000`, serving the same API except `initialize`. my-reverse-proxy reads its sources over `http(s)://` only, so it needs the port. Whoever reaches the port gets only ciphertext and refusals. `true`: the socket only, when nothing has to read over TCP. |
| `config_path` | The plaintext PKI folder of ca-api 0.2. See [Moving from 0.2](#moving-from-02). Must not be `data_folder` or overlap it, or the service stops at start. |

The settings of 0.2 (`config_path` alone) no longer start the service: `data_folder` and `unix_socket` are required.


## The keys

Both are 32 random bytes in base64 (44 characters): `openssl rand -base64 32`.

| Key | Encrypts | Where it lives | Who holds it |
|---|---|---|---|
| **files key** | `state.enc` and the journal, and every management call | the service's memory only, from `initialize` on | the operator / the admin client |
| **network key** | the answers to my-reverse-proxy: the CA certificate and the revoked list | in `state.enc` | my-reverse-proxy |

They must differ: `set-network-key` refuses the files key. Holding the network key gives only the CA certificate and the serials of the revoked certificates, never the ability to issue or to read a private key.

Losing the files key loses everything in the data folder: nobody can open it, the service included. Keep it, and back up `data_folder`.


## Initialize

After every start, hand the service its key over the unix socket:

```sh
S=/root/system-sockets/ca-api.http-sock

curl --unix-socket $S http://localhost/api/is-initialized
# {"initialized":false}

curl --unix-socket $S -XPOST http://localhost/api/initialize -d '{"key":"<files key>"}'
# {"initialized":true,"created":false,"cas":2,"certificates":41,"network_key":true,
#  "deleted":[],"legacy_plaintext_left":false}
```

| Answer | When |
|---|---|
| 200 `created: false` | The key opened `state.enc`. |
| 200 `created: true` | The data folder had no `state.enc`: this key created it, holding the CAs of `config_path` if there are any (`imported`). With no `"key"` the service makes one and returns it **once** as `"key"`. A key that was handed in is never returned. |
| 400 | The key is not base64 of 32 bytes, or there is none while `state.enc` exists. |
| 403 | The key does not open `state.enc`; or the request came over TCP; or the reverse proxy relayed it (`X-Forwarded-For`). The key travels in plain text, so it is taken over the unix socket only. |
| 409 | Already initialized since the start. |
| 500 | The data folder cannot be read or written, or `config_path` cannot be imported. The message says which file. |

- `deleted` lists what was swept out of the data folder as not encrypted.
- `legacy_plaintext_left: true`: the plaintext folder of 0.2 still holds a CA, and its keys are readable on the disk. Delete it (see below).
- **Until initialize** the service serves nothing. What my-reverse-proxy reads answers `503`, so the proxy keeps what it read last. Everything else answers `409`.


## Moving from 0.2

0.2 kept everything as plain files under `config_path`. To move:

1. Add `data_folder` (a new, empty folder of its own) and `unix_socket` to the settings, and keep `config_path`.
2. Start, and `initialize` with a new files key. Since there is no `state.enc` yet, the service reads every CA of `config_path` into the new state: the CA certificate and key, every issued certificate with its key, the revocations, the serial counter. `crl_number` and `crl.pem` are not needed and are not read. The answer says how many: `"imported":{"cas":1,"certificates":12}`.
   - The serial goes past the highest serial ever issued, whatever the `serial` file says.
   - 0.2 kept one record per email: a certificate it replaced by issuing the same email again is not in its `index.json`, and cannot be imported. From now on none is replaced.
   - Anything unreadable — a CA without its key, a broken `index.json`, a counter that is not a number — stops the import with `500`. Nothing is created, so nothing is lost silently. Fix it and initialize again.
3. Check the CAs over the encrypted API, and set the network key (`/api/set-network-key`).
4. **Delete the `config_path` folder** and drop `config_path` from the settings. The service only reads that folder, never changes or deletes it. Until it is deleted, its private keys lie on the disk in plain text, and every `initialize` warns about it.

The import happens once: when the state is created. Later starts never read `config_path` again.


## The API

All routes are where they were in 0.2. The calls that change something or hand out a secret moved from `GET`/`DELETE` with a query string to `POST` with an encrypted body (marked ✱). A query string is never encrypted, and a request without a body proves nothing.

**Plain**: no data in them.

| Call | |
|---|---|
| `POST /api/initialize` | `{"key"?}`, unix socket only, see [Initialize](#initialize) |
| `GET\|POST /api/is-initialized` | `{"initialized"}` |

**For my-reverse-proxy**: a `GET`, answered encrypted with the network key.

| Call | Answer, once decrypted |
|---|---|
| `GET /api/ca/v1/downloadCert?caName=` | the CA certificate, PEM (`application/x-pem-file`) |
| `GET /api/revoked/v1/list?caName=` | the serials of every certificate the CA revoked, a YAML array (`application/yaml`), ascending; `[]` when none is |

```yaml
- 5
- 6
- 7
```

A serial is the certificate's id. my-reverse-proxy refuses a client certificate of this CA whose serial is in the list. A revocation stays in the list for good: re-issuing the email adds a new certificate under a new serial.

`200` has `Content-Encoding: aes128gcm`, `Content-Type` of the data once decrypted, `Cache-Control: no-store`, a fresh salt every time ([my-reverse-proxy's standard](https://github.com/MyJetTools/my-reverse-proxy/blob/main/docs/encrypted-service-data.md)). `503` before initialize or while no network key is set: never the plain data. `404` for an unknown CA.

**Management**: encrypted with the files key. A `POST` body must come encrypted (`Content-Encoding: aes128gcm`), and the answer is encrypted with the same key.

| Call | Body | Answer, once decrypted |
|---|---|---|
| `GET /api/ca/v1/list` | — | `["xfin-ca", …]` |
| `POST /api/ca/v1/check` | `caName` | `Ok`; 404 when there is no such CA |
| `POST /api/ca/v1/generate` | `caName`, `organization`, `countryCode`, `city` | empty (RSA-4096, 10 years) |
| `POST /api/ca/v1/import` | multipart: `caName`, `cert` (PEM file), `privateKey` (PEM file) | empty |
| ✱ `POST /api/ca/v1/downloadPk` | `caName` | the CA private key, PEM. Journaled |
| `GET /api/certificates/v1/list?caName=` | — | `[{"id","cn","revoked","issued_at","revoked_at"}]`: every certificate, revoked ones included |
| `POST /api/certificates/v1/generate` | `caName`, `email` | `{"id","cn"}`: always a new certificate (CN = email, RSA-4096, 10 years) |
| ✱ `POST /api/certificates/v1/revoke` | `caName`, `id` — or `email` alone | `{"revoked":[ids]}`; from then on they are in the revoked list. `id`: that certificate (`409` when it is revoked already). `email` alone: every certificate of it that is not revoked |
| ✱ `POST /api/certificates/v1/downloadCert` | `caName`, `id` — or `email` alone, `password` | PKCS#12 (`application/x-pkcs12`): the certificate, its key, the CA. `email` alone: the newest certificate of it that is not revoked. No file name in a header: headers are not encrypted. Journaled |
| `POST /api/set-network-key` | `networkKey` | `{"set":true,"replaced","changed"}`. Again with another key: a rotation |
| `POST /api/journal` | `from`?, `to`? (unix seconds, from included, to not), `caName`?, `cn`?, `limit`? (100, at most 1000) | `{"records":[…],"unreadable":0}`, newest first |

- A plain body: `415`. A body the files key does not open: `400` (my-http-server). A replay: `403` (my-http-server), when the sender's clock is more than 10 seconds off the server's, or the body's salt was already accepted. Keep the clocks in sync (NTP).
- A call with no fields takes `{}`: an empty body cannot be encrypted.
- **A certificate's id is its serial**, unique within its CA: the number in the revoked list. An email may have several certificates: issuing it again adds one and replaces none, so a revoked certificate stays revoked. With both `id` and `email`, the certificate `id` must be that email's, or `404`.
- The `GET` lists prove nothing about the caller, but their answers are useless without the files key.
- Refusals and errors carry no data and are plain text.
- Swagger at `/swagger/index.html` documents the plain JSON of each call. It cannot send encrypted bodies.

### A client (FlUrl)

my-http-server's encrypted bodies (`docs/http-actions/encrypted-requests.md`), which FlUrl builds:

```toml
flurl = { tag = "0.7.0", git = "https://github.com/MyJetTools/fl-url.git", features = ["encryption"] }
```

```rust
use flurl::body::HttpRequestBody;
use flurl::my_http_utils::HttpBodyEncryptionKey;
use flurl::FlUrl;

let key = HttpBodyEncryptionKey::from_base64(&files_key)?;

let mut response = FlUrl::new("http+unix:///root/system-sockets/ca-api.http-sock")
    .append_path_segment("api")
    .append_path_segment("certificates")
    .append_path_segment("v1")
    .append_path_segment("generate")
    .encrypted(&key)
    .post(HttpRequestBody::as_json(&serde_json::json!({ "caName": "xfin-ca", "email": "alice@example.com" })))
    .await?;

let encrypted = response
    .get_header_case_insensitive("content-encoding")?
    .is_some_and(|coding| coding.eq_ignore_ascii_case("aes128gcm"));
let body = response.get_body()?.into_vec(16 * 1024 * 1024).await?;
// A plain answer is a refusal, an error, or empty.
let data = if encrypted { key.decrypt(&body)? } else { body };
```

A client in another language implements RFC 8188 (HMAC-SHA-256, AES-128-GCM). The plain text of a request is the sender's clock (unix microseconds, `i64`, 8 bytes, little-endian), then the body. An answer has no clock.


## my-reverse-proxy

my-reverse-proxy reads two things per CA, both encrypted with the network key: the CA certificate, and the YAML array of revoked serials. It loads a source from a file, over ssh or over `http(s)://`, not from a unix socket, so it reads over the TCP port:

```yaml
client_certificate_ca:
  - id: xfin-ca
    ca: http://ca-api:8000/api/ca/v1/downloadCert?caName=xfin-ca
    revocation_list: http://ca-api:8000/api/revoked/v1/list?caName=xfin-ca
```

my-reverse-proxy reads `revocation_list` as a CRL today. Reading it as the YAML array of serials is a change on its side.

Order: put the network key into my-reverse-proxy, then `set-network-key` it here. In between, the urls answer `503` and the proxy keeps what it has. To rotate, give the proxy the new key next to the old one, `set-network-key` the new one here, then remove the old one from the proxy.


## The data folder

| File | What |
|---|---|
| `state.enc` | Every CA with its key, every certificate it issued with its key (kept by id, revoked ones included), the serial counter, the network key: JSON in one envelope with the AAD `state`. Written atomically. |
| `journal/<yyyy-mm>.log` | The journal of a UTC month: one envelope per line, one record each, with the AAD `journal`. |

An envelope is base64 of `nonce (12) ‖ ciphertext ‖ tag (16)`, AES-256-GCM with the files key. Every file is `0600`.

### The journal

| `event` | Fields |
|---|---|
| `initialized` | The data folder was created. |
| `unlocked` | The key was handed after a start. |
| `ca_generated` | `ca` |
| `ca_imported` | `ca`, `by` (`api` / `legacy`), `certificates` (from 0.2) |
| `cert_issued` | `ca`, `cn`, `serial` |
| `cert_revoked` | `ca`, `cn`, `serial` |
| `pfx_downloaded` | `ca`, `cn`, `serial` |
| `ca_key_downloaded` | `ca` |
| `network_key_set` | `by` (`new` / `replaced`), never the key |

Old months are files of their own: delete `journal/<yyyy-mm>.log` to drop one.


## Deploy

```yaml
services:
  ca-api:
    image: ghcr.io/my-jet-tools/ca-api:<tag>
    container_name: ca-api
    restart: always
    deploy:
      resources:
        limits:
          memory: 64Mb
    volumes:
      - ./.ca-api:/root/.ca-api:ro
      - ./data:/root/data                              # the data folder: the service's alone
      - ~/unix-sockets/system:/root/system-sockets     # the socket the key is handed over
    networks:
      - docker_net                                     # my-reverse-proxy reads http://ca-api:8000
    logging:
      options:
        max-size: 512Kb
        max-file: 1

networks:
  docker_net:
    external: true
```

```yaml
# ./.ca-api
data_folder: /root/data
unix_socket: /root/system-sockets/ca-api.http-sock
```

No port needs publishing on the host: my-reverse-proxy reaches `ca-api:8000` over the docker network. After every start, `POST /api/initialize` over the socket. Until then my-reverse-proxy keeps the CA and the revoked list it read last.

PKCS#12 bundles use the modern format (AES-256-CBC, HMAC-SHA-256, PBKDF2-SHA-256). macOS Keychain, Windows 10 1809 and later, and modern Linux trust stores accept them as they are.
