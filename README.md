# ca-api

A CA for client certificates over HTTP: CA roots, issuing and revoking client certificates, PKCS#12 bundles, and the list of revoked certificates my-reverse-proxy refuses. There is no CRL. Pure Rust (`rcgen` + `openssl` FFI), no `easy-rsa` or `openssl` CLI at runtime.

**Everything is encrypted.** The aim: whoever gets into the machine — its disk, its unix sockets, the container network — can neither read anything (CA names, emails, certificates, private keys) nor change anything (issue, revoke, import). At most they can break the service.

- On the disk there is only encrypted data: `state.enc` and the journal, AES-256-GCM.
- The key that encrypts them — the **encryption key** — is never on the disk. It lives in the service's memory, from `initialize` until the process ends. After every start the service knows nothing until it is handed the key over its unix socket: `initialize` is the one call that is not encrypted.
- Every other call is encrypted. The encryption key opens only the calls that manage the keys: setting the network key, changing the encryption key, rolling it back. The **network key**, kept in the encrypted state, opens everything else, and encrypts what my-reverse-proxy reads. A request without the right key is refused before anything runs. A captured request cannot be sent again.
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
| `data_folder` | The folder the service keeps everything in, encrypted. **It belongs to the service alone:** once the key opens it, everything in it except `state.enc`, `journal/<yyyy-mm>.log` and `archive/<YYYYMMDDhhmmss>/` is deleted. |
| `unix_socket` | The socket the API is served on. Required, since `POST /api/initialize` is taken only here. A stale socket file is removed on start. |
| `unix_socket_only` | `false` (the default): also TCP `0.0.0.0:8000`, serving the same API except `initialize`. my-reverse-proxy reads its sources over `http(s)://` only, so it needs the port. Whoever reaches the port gets only ciphertext and refusals. `true`: the socket only, when nothing has to read over TCP. |
| `config_path` | The plaintext PKI folder of ca-api 0.2. See [Moving from 0.2](#moving-from-02). Must not be `data_folder` or overlap it, or the service stops at start. |

The settings of 0.2 (`config_path` alone) no longer start the service: `data_folder` and `unix_socket` are required.


## The keys

Both are 32 random bytes in base64 (44 characters): `openssl rand -base64 32`.

| Key | Encrypts at rest | Opens the calls | Where it lives | Who holds it |
|---|---|---|---|---|
| **encryption key** | the data folder: `state.enc`, the journal, the archives | `set-network-key`, `change-key`, `rollback` — nothing else | the service's memory only, from `initialize` on | the operator; it can stay off-line once the network key is set |
| **network key** | — | every other encrypted call; and it encrypts what my-reverse-proxy reads | in `state.enc` | the admin client, my-reverse-proxy |

- They must differ: `set-network-key` refuses the encryption key, `change-key` refuses the network key.
- Whoever holds the network key can make every call but those three: issue, revoke, import, read the journal and the private keys. The encryption key is needed to set or replace the network key, to change the encryption key, to roll it back, and after every start for `initialize`.
- Losing the encryption key loses everything in the data folder: nobody can open it, the service included. Keep it, and back up `data_folder`.

### Which key a call takes

| Call | The request | The answer |
|---|---|---|
| `POST /api/initialize` | **plain** — the one plain call: it hands the encryption key over, unix socket only | plain |
| `GET\|POST /api/is-initialized` | plain: no key, no data | plain `{"initialized"}` |
| `POST /api/set-network-key` | encryption key | encryption key |
| `POST /api/change-key` | encryption key (the current one); the new key is in the body | encryption key: the old one, the one the call came with |
| `POST /api/rollback` | encryption key (the current one); the archive's key is in the body | encryption key: the one the call came with |
| `POST /api/ca/v1/check`, `generate`, `import`, `downloadPk` | network key | network key |
| `POST /api/certificates/v1/generate`, `revoke`, `downloadCert` | network key | network key |
| `POST /api/journal` | network key | network key |
| `GET /api/ca/v1/list`, `GET /api/certificates/v1/list` | a `GET`: no body | network key |
| `GET /api/ca/v1/downloadCert`, `GET /api/revoked/v1/list` (my-reverse-proxy) | a `GET`: no body | network key |

A `GET` carries nothing to encrypt and proves nothing about the caller: its answer is useless without the network key.

### Changing the encryption key

`POST /api/change-key` `{"newKey"}`: the body comes encrypted with the current encryption key, and hands the new one over. Under the hood:

1. The data folder as it is — `state.enc` and the journal, still under the old key — is copied to `archive/<YYYYMMDDhhmmss>` (UTC; `-2` for a second change within the same second).
2. A snapshot under the new key — the state and every journal line — takes its place, and work goes on from it. `POST /api/journal` keeps the whole history.
3. From the next request on only the new key opens the folder — after a restart too — and the three calls it opens: a body under the old key is refused (`400`). The answer to this call is still under the old key, the one it came with: `{"changed":true,"archive":"20261119143005","journal_records":120,"journal_unreadable":0}`.

The network key is not touched, and the new key must not be it (`403`). The same key again: `{"changed":false}`, nothing done.

A crash halfway loses nothing: `state.enc` is replaced atomically, and whichever key opens it is the key. If the answer never came, initialize with the new key, and with the old one if the new one is refused. The next `initialize` finishes or drops what the crash left.

### Rolling back

`POST /api/rollback` `{"key","archive"?}`: the body comes encrypted with the current encryption key, and hands over the key an archive was encrypted with. The service opens the archive — `archive`, or with none named the newest one the key opens — with that key. When the key fits, the archive is put back, and the key becomes the encryption key, for the calls too: `{"rolled_back":true,"restored":"20261119143005","archive":"20261119150210","network_key":true}`, under the key the call came with.

- It comes as it was then: the state, the journal, the network key of then. Everything done since is in the archive of what was replaced.
- What was in place goes to the archive first, under its key, so a rollback loses nothing and is undone the same way: roll back with the other key.
- `403` when the key opens no archive (or not the one named), `404` when there is no such archive.

**Delete the archives you no longer need**: `rm -r data/archive/<YYYYMMDDhhmmss>`. The service never deletes them. An archive opens with the key of its time: if the key was changed because it leaked, whoever holds the old key and gets the disk reads the archive — the CAs and their private keys as they were.


## Initialize

After every start, hand the service its key over the unix socket:

```sh
S=/root/system-sockets/ca-api.http-sock

curl --unix-socket $S http://localhost/api/is-initialized
# {"initialized":false}

curl --unix-socket $S -XPOST http://localhost/api/initialize -d '{"key":"<encryption key>"}'
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
- **After the first initialize**, set the network key — under the encryption key — before anything else: until there is one, the calls it opens answer `409`, and what my-reverse-proxy reads answers `503`.


## Moving from 0.2

0.2 kept everything as plain files under `config_path`. To move:

1. Add `data_folder` (a new, empty folder of its own) and `unix_socket` to the settings, and keep `config_path`.
2. Start, and `initialize` with a new encryption key. Since there is no `state.enc` yet, the service reads every CA of `config_path` into the new state: the CA certificate and key, every issued certificate with its key, the revocations, the serial counter. `crl_number` and `crl.pem` are not needed and are not read. The answer says how many: `"imported":{"cas":1,"certificates":12}`.
   - The serial goes past the highest serial ever issued, whatever the `serial` file says.
   - 0.2 kept one record per email: a certificate it replaced by issuing the same email again is not in its `index.json`, and cannot be imported. From now on none is replaced.
   - Anything unreadable — a CA without its key, a broken `index.json`, a counter that is not a number — stops the import with `500`. Nothing is created, so nothing is lost silently. Fix it and initialize again.
3. Set the network key (`/api/set-network-key`, under the encryption key), and check the CAs over the API (under the network key).
4. **Delete the `config_path` folder** and drop `config_path` from the settings. The service only reads that folder, never changes or deletes it. Until it is deleted, its private keys lie on the disk in plain text, and every `initialize` warns about it.

The import happens once: when the state is created. Later starts never read `config_path` again.


## The API

All routes of 0.2 are where they were. The calls that change something or hand out a secret moved from `GET`/`DELETE` with a query string to `POST` with an encrypted body (marked ✱). A query string is never encrypted, and a request without a body proves nothing. Which key each call takes: [the table](#which-key-a-call-takes).

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

**The keys**: under the encryption key. The body comes encrypted with it, and the answer is encrypted with it — with the key the call came with.

| Call | Body | Answer, once decrypted |
|---|---|---|
| `POST /api/set-network-key` | `networkKey` | `{"set":true,"replaced","changed"}`. Again with another key: a rotation. From the next request on, the calls take the new network key alone |
| `POST /api/change-key` | `newKey` | `{"changed","archive","journal_records","journal_unreadable"}`. See [Changing the encryption key](#changing-the-encryption-key) |
| `POST /api/rollback` | `key`, `archive`? | `{"rolled_back":true,"restored","archive","network_key"}`. See [Rolling back](#rolling-back) |

**Everything else**: under the network key. A `POST` body comes encrypted with it, and the answer is encrypted with it.

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
| `POST /api/journal` | `from`?, `to`? (unix seconds, from included, to not), `caName`?, `cn`?, `limit`? (100, at most 1000) | `{"records":[…],"unreadable":0}`, newest first |

- A plain body: `415`. A body under the other key of the two: `403` (`this call takes the network key`, or `the encryption key`). Before a network key is set, a call it opens: `409`.
- my-http-server's own refusals: `400` when no key of the service opens the body (another key, damaged, cut short); `403` for a replay, when the sender's clock is more than 10 seconds off the server's, or the body's salt was already accepted. Keep the clocks in sync (NTP).
- A call with no fields takes `{}`: an empty body cannot be encrypted.
- **A certificate's id is its serial**, unique within its CA: the number in the revoked list. An email may have several certificates: issuing it again adds one and replaces none, so a revoked certificate stays revoked. With both `id` and `email`, the certificate `id` must be that email's, or `404`.
- Refusals and errors carry no data and are plain text.
- Swagger at `/swagger/index.html` documents the plain JSON of each call. It cannot send encrypted bodies.

### From 0.3

- The calls of the CAs, the certificates and the journal take the **network key** now, not the key of `initialize`. After the upgrade, initialize, and if the state has no network key yet, set one first: `set-network-key` under the encryption key.
- `change-files-key` is `change-key`, `rollback-files-key` is `rollback`; both take the encryption key. `files-key-archives` and `delete-files-key-archive` are gone: delete an archive from the disk.
- The journal records of 0.3 are read as they are: `files_key_changed` as `key_changed`, `files_key_rolled_back` as `rolled_back`.

### A client (FlUrl)

my-http-server's encrypted bodies (`docs/http-actions/encrypted-requests.md`), which FlUrl builds:

```toml
flurl = { tag = "0.7.0", git = "https://github.com/MyJetTools/fl-url.git", features = ["encryption"] }
```

```rust
use flurl::body::HttpRequestBody;
use flurl::my_http_utils::HttpBodyEncryptionKey;
use flurl::FlUrl;

// The network key; set-network-key, change-key and rollback take the encryption key instead.
let key = HttpBodyEncryptionKey::from_base64(&network_key)?;

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

Order: put the network key into my-reverse-proxy, then `set-network-key` it here. In between, the urls answer `503` and the proxy keeps what it has. To rotate, give the proxy the new key next to the old one, `set-network-key` the new one here, then remove the old one from the proxy. The admin client takes the new network key from the same moment: the old one opens no call any more.


## The data folder

| File | What |
|---|---|
| `state.enc` | Every CA with its key, every certificate it issued with its key (kept by id, revoked ones included), the serial counter, the network key: JSON in one envelope with the AAD `state`. Written atomically. |
| `journal/<yyyy-mm>.log` | The journal of a UTC month: one envelope per line, one record each, with the AAD `journal`. |
| `archive/<YYYYMMDDhhmmss>/` | `state.enc` and `journal/` as they were before a change of the encryption key or a rollback, under the encryption key of then. Written whole or not at all. Never deleted by the service. |
| `journal.new/` | Only while the encryption key changes or a rollback runs: the journal of what takes the place of the folder. A crash leaves it to the next `initialize`, which puts it in place or drops it. |

An envelope is base64 of `nonce (12) ‖ ciphertext ‖ tag (16)`, AES-256-GCM with the encryption key. Every file is `0600`.

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
| `key_changed` | `archive`: where the folder as it was went, under the old key. Never a key |
| `rolled_back` | `restored`: the archive put back; `archive`: where what was in place went |
| `archive_deleted` | 0.3 only: `archive` |

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
