# archivindex-http-client

A Rust library of HTTP clients that capture the request and response messages of each exchange. A
fetch is exactly one request and one response on a new connection. No backend follows redirects,
retries, keeps cookies, decodes content, pools connections, or reads proxy settings from the
environment, so the stored messages describe everything that happened.

## Backends

Every backend implements the `Backend` trait and returns a `CapturedExchange`.

| Backend          | Feature | Protocols           | TLS       | Stored messages                              |
| ---------------- | ------- | ------------------- | --------- | -------------------------------------------- |
| `Recorder`       |         | HTTP/1.1            | rustls    | Exact bytes                                  |
| `ReqwestBackend` |         | HTTP/1.1            | rustls    | Reconstructed                                |
| `WreqBackend`    | `wreq`  | HTTP/1.1 and HTTP/2 | BoringSSL | Exact for HTTP/1.1, reconstructed for HTTP/2 |

`Recorder` serializes the request itself and stores the response verbatim, so header spelling,
reason phrases, chunk extensions, and trailers are the origin's. `ReqwestBackend` rebuilds both
messages from the parts `reqwest` exposes. `WreqBackend` adds browser emulation, and HTTP/2 when
asked for it; see [the `wreq` feature](#the-wreq-feature).

## Usage

```rust,no_run
use archivindex_http_client::recorder::Recorder;
use archivindex_http_client::{Backend, Request};
use http::{HeaderMap, Method};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let captured = Recorder::new().fetch(Request {
        method: &Method::GET,
        target: &"https://www.example.com/".parse()?,
        headers: &HeaderMap::new(),
        body: None,
    })?;

    println!("{}", captured.response_metadata.status);
    println!("{}", String::from_utf8_lossy(&captured.request));
    println!("{} body bytes", captured.entity_body()?.len());

    Ok(())
}
```

`Backend::fetch_by` takes a deadline as well. Calls are synchronous, and the `reqwest` and `wreq`
backends may be called from inside a Tokio runtime, because each fetch runs on a runtime and thread
of its own.

Every backend adds a `host` header when the caller supplies none, and an HTTP/1.1 request without a
`connection` header gets `connection: close`. A provided body is framed with `content-length`,
replacing any framing headers the caller supplied.

## Captured exchanges

A `CapturedExchange` holds the stored request and response messages, both in HTTP/1 form, and these
facts about the exchange:

- `fidelity` says whether the stored messages are the exact bytes of an HTTP/1 exchange
  (`Exact`), or were rebuilt from parsed parts of an HTTP/1 exchange (`ReconstructedHttp1`) or an
  HTTP/2 exchange (`ReconstructedHttp2`).
- `tls_version` is the negotiated TLS version. It is absent for a plaintext exchange, and when the
  backend cannot observe it. No backend guesses a version.
- `ip_address` is the origin address. It is absent for a proxied exchange.
- `truncated` says why a response is incomplete (`Length`, `Time`, or `Disconnect`), and is absent
  for a complete response.
- `date` and `fetch_time` record when network activity began and how long the exchange took.

The stored response starts at the final status line, since interim `1xx` responses are discarded.
`stored_body` returns the bytes after its header section as they were stored, and `entity_body`
returns them with transfer coding removed. Content coding is never removed. `entity_body` fails for
a chunked response that was truncated, because its chunked body is incomplete.

The `message` module parses stored messages, the `body` module removes transfer coding from them,
the `framing` module finds the end of a response as its bytes arrive, and the `reconstruct` module
builds HTTP/1.1 messages from parsed parts.

## Limits and timeouts

Each backend starts with a 30 second timeout for connecting, a 30 second timeout for I/O, and a
256 MiB limit on the stored response. Every setter accepts `None` to remove its bound.

The response limit counts stored message bytes, including the header section and transfer framing.
A response that ends exactly at the limit is complete, not truncated.

Failures are reported in the same way by every backend. A failure before a complete response header
section is an error, as is a header section that does not fit the response limit. After the header
section, a size limit, a disconnect, a timeout, or a passed deadline returns the response received
so far, with `truncated` set.

The timeouts cover slightly different spans in each backend:

| Backend          | `connect_timeout`                  | `io_timeout`                                             | Deadline     |
| ---------------- | ---------------------------------- | -------------------------------------------------------- | ------------ |
| `Recorder`       | Each resolved address              | Each read or write                                       | Excludes DNS |
| `ReqwestBackend` | Connecting, with the TLS handshake | Each wait for the header section or for more of the body | Wall clock   |
| `WreqBackend`    | Connecting, with DNS and TLS       | Idle time after connecting                               | Includes DNS |

## Proxies

Each backend has a `proxy` setter for a SOCKS5 proxy:

```rust,no_run
use archivindex_http_client::recorder::Recorder;

let backend = Recorder::new().proxy(Some("socks5h://127.0.0.1:1080"))?;
# Ok::<(), archivindex_http_client::InvalidProxy>(())
```

Use `socks5h://` to resolve destination hostnames through the proxy, or `socks5://` for local DNS.
The default proxy port is 1080. Username and password authentication is supported with
`socks5h://user:password@host:port`, with reserved characters in the credentials percent-encoded.
Every backend accepts the same proxy URIs and rejects other schemes.

A proxy failure never falls back to a direct connection. Timeouts and deadlines also bound SOCKS
negotiation. The stored messages exclude proxy negotiation and authentication. Proxied exchanges
have no `ip_address`, because the socket peer is the proxy and SOCKS does not reliably identify the
origin address.

## The reqwest backend

`ReqwestBackend` stores the request line, the fields, and the field order that `reqwest` sends,
including the `accept: */*` it adds when the caller supplies no `accept` header. The request target
is the one `reqwest` sends after normalizing the URI (for example, `/a/../b` becomes `/b`), while
`CapturedExchange::target_uri` remains the URI the caller asked for.

The stored response differs from the origin's bytes in these ways:

- Field names are lowercased, and the whitespace around field values is normalized.
- The reason phrase is the canonical one for the status code.
- A chunked body is stored chunked, with one chunk for each piece of body data `reqwest` delivers.
  Chunk boundaries are therefore not necessarily the origin's, and chunk extensions are lost.
  Trailers are kept.

Content coding is kept. The backend turns off each of `reqwest`'s decoders, so this holds even when
another crate in the build enables `reqwest`'s `gzip`, `brotli`, `deflate`, or `zstd` feature.

The negotiated TLS version is reported for direct connections only, because `reqwest` does not
expose it for a connection made through a SOCKS proxy.

Use `Recorder` when the stored bytes must be the ones that crossed the connection.

## The `wreq` feature

The `wreq` feature adds `WreqBackend`, which performs exchanges through BoringSSL with the TLS and
HTTP/2 settings of a browser profile. It is off by default because of what it requires:

- Rust 1.98 or later (the rest of the crate requires Rust 1.88).
- A C and C++ compiler, CMake, and libclang, to build BoringSSL.
- A `wreq` fork that lets the backend observe plaintext connection traffic and negotiated TLS
  versions, together with unreleased `btls` revisions that the fork depends on.

Cargo does not propagate dependency patches, so a workspace that enables the feature must copy
these entries from this repository's [workspace manifest](../../Cargo.toml) into its own:

```toml
[patch.crates-io]
wreq = { git = "https://github.com/travisbrown/wreq", rev = "108701e00f33b40132e78d28abce8b4f6e3a6b19" }
btls = { git = "https://github.com/0x676e67/btls", rev = "9d859deefab0183e2fccf91204c818c8d1805b27" }
btls-sys = { git = "https://github.com/0x676e67/btls", rev = "9d859deefab0183e2fccf91204c818c8d1805b27" }
tokio-btls = { git = "https://github.com/0x676e67/btls", rev = "9d859deefab0183e2fccf91204c818c8d1805b27" }
```

The crate pins exact versions of `wreq`, `wreq-proto`, and `wreq-util`, because the fork tracks one
`wreq` release.

### Profiles

A backend is created with a profile, and `profile` replaces it:

```rust,ignore
use archivindex_http_client::wreq::{WreqBackend, parse_profile};
use wreq_util::Profile;

let backend = WreqBackend::new(Profile::Chrome136);
let backend = backend.profile(parse_profile("firefox_136")?);
```

Profiles are the `Profile` type of `wreq-util`. An application that names its variants must depend
on `wreq-util` at the exact version this crate pins. `parse_profile` looks a profile up by its
configuration name, such as `chrome_136`, and fails for an unknown name, so an application that
selects profiles by name needs no dependency of its own.

The profile supplies the TLS settings, the HTTP/2 settings, and the default request headers with
their order and casing. Request headers passed to a fetch override the profile's values. Browser
emulation may improve access, but it does not guarantee that a site accepts the request.

### HTTP/2

HTTP/2 is used only by a backend that enables it:

```rust,ignore
let backend = WreqBackend::new(Profile::Chrome136).http2(true);
```

With HTTP/2 enabled, the backend offers the profile's ALPN protocols and uses HTTP/2 when the
origin selects it, falling back to HTTP/1.1 otherwise. Without it, the backend offers only
`http/1.1`. A browser profile normally offers `h2` too, so the `ClientHello` of a backend without
HTTP/2 differs from the emulated browser's in its ALPN extension.

An HTTP/2 exchange is stored as HTTP/1.1 messages, with `Fidelity::ReconstructedHttp2`. The stored
messages are a reconstruction, not a transcript of binary HTTP/2 frames:

- Pseudo-headers become the request method, target, and `host` header, or the response status.
  Reason phrases and the header order of the response are produced by the reconstruction.
- The request has the finalized headers that the codec sends, after defaults, framing, and the
  removal of connection-specific headers, in the order and casing of the profile. The outgoing
  frames must show one complete request. A second stream or connection fails the fetch.
- The response keeps content-encoded data and repeated headers. A response with a body is stored
  with generated chunked framing in place of the original `content-length`, so that trailers stay
  separate from the initial headers. Responses to `HEAD`, and `204` and `304` responses, keep their
  bodiless form and their representation lengths.
- The original frame bytes, HPACK state, and framing declarations are not kept.

### Capture contract

Each fetch owns one client, one connection observer, and one current-thread Tokio runtime on a
scoped thread, and disposes of its tasks and connection before it returns. This favors isolation
over reuse, and concurrent fetches cannot share observer state or connections. A system DNS lookup
that is already running may finish in the background after a timeout.

HTTP/1 messages are the observed plaintext bytes, with reason phrases, header formatting, duplicate
headers, chunk extensions, and trailers as they crossed the connection. A codec error fails an
unfinished capture unless the observer has already found the end of the message or a truncation. A
failed write or flush also fails an unfinished capture, while a failed shutdown does not invalidate
a complete response.

For HTTP/2, the response limit counts the reconstructed message, not connection traffic or payload
bytes alone, and the codec applies its header-list bound to headers and trailers before
reconstruction. Idle time tracks outgoing request frames and decoded response progress, so
connection control traffic cannot keep a stalled response alive.

`tls_cert_store` replaces the default Mozilla root certificates. There is no setter for an
arbitrary `wreq` client, because a client with redirects, retries, pooling, or other protocol
settings would make the stored messages misleading.

## Validation

All three backends run one [conformance suite](tests/support/backend_conformance.rs) against
scripted loopback servers. It covers framing, truncation, timeouts, TLS, and concurrency, and a
[second suite](tests/support/proxy_conformance.rs) covers proxies. `Recorder` and `WreqBackend`
also run an [exact capture suite](tests/support/exact_conformance.rs). Further tests cover the
reconstruction that `ReqwestBackend` performs, profile selection, and HTTP/2. No test makes a
request outside the loopback interface.

Run the tests from the workspace root, without and with the `wreq` feature:

```console
cargo test --locked
cargo test --locked --features wreq
```

Run the response framing benchmarks with:

```console
cargo bench --bench response_capture
```

The cases cover small responses, long headers, and long chunk extensions, each delivered in 1-byte,
16-byte, and 8 KiB fragments. They use in-memory messages and make no network requests.

## License

Licensed under the GNU General Public License, version 3. See [LICENSE](LICENSE).
