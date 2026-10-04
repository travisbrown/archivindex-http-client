# archivindex-http-client

HTTP clients for the [Archivindex](https://github.com/travisbrown/archivindex) projects that store
the request and response of each exchange. Every fetch makes one request on a new connection.
Clients do not follow redirects, retry, keep cookies, decode content, pool connections, or read
proxy settings from the environment.

The workspace also contains
[`archivindex-http-client-challenge`](archivindex-http-client-challenge/README.md). Its `Session`
wraps a client, automatically answers Sucuri, Varnish, and Simply.com challenges, and retains
clearance cookies. It returns every exchange, including challenge and verification responses.

## Clients

All clients implement `Client` and return a `CapturedExchange`.

| Client          | Feature | Protocols           | TLS       | Stored messages                              |
| --------------- | ------- | ------------------- | --------- | -------------------------------------------- |
| `Recorder`      |         | HTTP/1.1            | rustls    | Exact bytes                                  |
| `ReqwestClient` |         | HTTP/1.1            | rustls    | Reconstructed                                |
| `WreqClient`    | `wreq`  | HTTP/1.1 and HTTP/2 | BoringSSL | Exact for HTTP/1.1, reconstructed for HTTP/2 |

Use `Recorder` when the original HTTP/1 bytes matter. `ReqwestClient` reconstructs messages from
parsed parts. `WreqClient` adds browser emulation and optional HTTP/2 support.

## Usage

```rust,no_run
use archivindex_http_client::recorder::Recorder;
use archivindex_http_client::{Client, Request};
use http::{HeaderMap, Method};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let captured = Recorder::new().fetch(Request {
        method: &Method::GET,
        target: &"https://www.example.com/".parse()?,
        headers: &HeaderMap::new(),
        body: None,
    })?;

    println!("{}", captured.response_metadata.status);
    println!("{} body bytes", captured.entity_body()?.len());
    Ok(())
}
```

`Request` borrows its method, target, headers, and body. `Client::fetch_by` also takes an absolute
`Instant` deadline. Calls are synchronous. The reqwest and wreq clients run each fetch on a scoped
thread with its own Tokio runtime, so callers can already be inside a runtime.

Clients add a missing `host` header and default HTTP/1.1 requests to `connection: close`. They
remove caller-supplied `content-length` and `transfer-encoding` fields and frame a supplied body
with its actual length. `Some(&[])` supplies an empty body; `None` supplies no body.

Targets must be absolute HTTP or HTTPS URIs. Validation happens before network activity. URI
userinfo is removed from the transport target; only an explicit `authorization` header supplies
origin credentials. `CapturedExchange::target_uri` retains the URI supplied by the caller.

## Stored exchanges

The request and response are stored in HTTP/1 form, even when the connection used HTTP/2.
`fidelity` distinguishes exact bytes from reconstructed messages; `http_protocol` records the
protocol used on the connection. Interim `1xx` responses are discarded, so the stored response
starts at the final status line.

`response_metadata` contains the status, header values, and body offset. `stored_body()` returns
the bytes after the header section without changing them. `entity_body()` removes transfer
coding and preserves content coding. It returns an empty body for `HEAD`, `204`, and `304`
responses, and an error when a declared chunked body has incomplete framing or trailers.

`tls_version` is the negotiated TLS version when the client can observe it. It is absent for
plaintext exchanges and for reqwest's SOCKS connections. `ip_address` identifies the origin and
is absent for proxied exchanges. `date` records when network activity began; `fetch_time` records
its elapsed duration. `truncated` is absent for a complete response and otherwise records
`Length`, `Time`, or `Disconnect`.

### Reconstruction

The reqwest client builds the stored request from the parts it submits, after URL normalization
and the addition of default headers. For example, `/a/../b` becomes `/b`. This describes the
expected request; reqwest does not expose the bytes written to the connection.

Reconstructed response headers use lowercase names, normalized whitespace, and the status code's
canonical reason phrase. Repeated fields and content-encoded data are preserved. A chunked body
gets one generated chunk per delivered body frame, followed by its trailers. The origin's chunk
boundaries and extensions are lost. Content decoding stays disabled even when another dependency
enables reqwest's compression features.

Exact HTTP/1 captures preserve header casing, duplicate fields, reason phrases, chunk extensions,
and trailers. The recorder serializes its own request and stores the response verbatim. Wreq
observes plaintext transport reads and writes.

## HTTP policies and stored messages

`prepare` combines request headers, normalizes URL targets, and rejects or redacts embedded
credentials. `redirect` resolves HTTP locations and rewrites methods, bodies, and origin-specific
headers. The challenge crate's `Session` combines redirects and challenge answers in one sequence
when redirect following is enabled.

`retry` supplies bounded exponential delays, `Retry-After` parsing (including obsolete HTTP date
forms), and status, transport-error, and truncation classification. Callers decide whether a
request is safe to repeat and perform the wait. A configured response length bound is not treated
as a transient failure.

`conditional` parses combined `Vary` declarations, matches selecting request fields, and applies
ETag and Last-Modified validators. Missing and empty fields remain distinct. An unreadable `Vary`
declaration or unavailable selecting request makes the representation unselectable. Persistence
and application-specific representation identities belong to the caller.

`body::entity_body` requires complete transfer framing. For existing stored messages,
`body::entity_body_with(message, Decoding::Stored)` also accepts a body already dechunked under
stale transfer headers, and a final zero-size chunk without its trailers. Both policies preserve
content coding and reject unsupported transfer codings or incomplete chunk data.
`body::message_body` returns the stored bytes after the header section without decoding.

## Limits and timeouts

Connection and I/O timeouts default to 30 seconds. The stored response limit defaults to 256 MiB.
Their setters accept `None` to remove a bound.

The response limit includes the final header section and transfer framing. It counts stored
bytes, including generated framing for reconstructed responses. Each header section has a
separate 64 KiB bound. Interim headers do not consume the final response limit. A response that
ends exactly at the limit is complete.

A failure before a complete final header section is an error. After that section, a size limit,
disconnect, timeout, or expired deadline retains the captured prefix and sets `truncated`.
Malformed framing remains an error. I/O failures preserve their error kind, including
`ConnectionRefused` and `TimedOut`.

| Client          | Connection timeout | I/O timeout                                      | Deadline     |
| --------------- | ------------------ | ------------------------------------------------ | ------------ |
| `Recorder`      | Each address tried | Each socket read or write                        | Excludes DNS |
| `ReqwestClient` | DNS, TCP, and TLS  | Wait for the response head, then each body frame | Wall clock   |
| `WreqClient`    | DNS, TCP, and TLS  | Idle time after connecting                       | Wall clock   |

The recorder uses blocking DNS. Reqwest's first I/O wait includes connecting and sending the
request. Wreq measures HTTP/2 progress through outgoing request frames and decoded response data;
connection control traffic cannot keep a stalled exchange alive. A system DNS lookup already
running when an asynchronous client times out may finish in the background.

## TLS and proxies

The recorder and reqwest trust `webpki-roots` and explicitly select the `aws-lc-rs` crypto provider.
They do not depend on the operating system trust store or the process's default provider. Their
`tls_config` setters accept a replacement configuration, for example to trust a private
certificate authority. Both restrict ALPN to `http/1.1`. Wreq accepts custom roots through
`tls_cert_store`. Default configurations verify certificates and hostnames.

Every client accepts the same SOCKS5 proxy URIs:

```rust,no_run
use archivindex_http_client::recorder::Recorder;

let client = Recorder::new().proxy(Some("socks5h://127.0.0.1:1080"))?;
# Ok::<(), archivindex_http_client::InvalidProxy>(())
```

Use `socks5h://` for proxy DNS or `socks5://` for local DNS. The default port is 1080. Optional
username and password credentials are percent-encoded, as in
`socks5h://user:p%40ssword@host:1080`. Other schemes are rejected.

Proxy failures never fall back to direct connections. SOCKS negotiation is subject to transport
timeouts and deadlines, and is excluded from stored messages. Proxied exchanges omit the origin
IP because the socket peer is the proxy and SOCKS does not reliably identify the origin address.

## Optional wreq client

Enable the `wreq` feature for browser emulation. It requires Rust 1.98 or later, a C and C++
compiler, CMake, and libclang to build BoringSSL. The other clients require Rust 1.88.

```rust,ignore
use archivindex_http_client::wreq::{WreqClient, parse_profile};

let client = WreqClient::new(parse_profile("chrome_136")?);
let http2_client = client.clone().http2(true);
let firefox = client.profile(parse_profile("firefox_136")?);
```

The profile supplies TLS settings, default headers, header ordering and casing, and HTTP/2
settings. Explicit request headers override profile values. Unknown profile names return an
error. Applications can also supply `wreq_util::Profile` directly by depending on the pinned
`wreq-util` version. Browser emulation does not guarantee access to a site.

HTTP/2 is disabled by default, restricting ALPN to `http/1.1`. With `.http2(true)`, the client
offers the profile's protocols and uses HTTP/2 when the server selects it, otherwise HTTP/1.1.
Restricting ALPN changes that part of the emulated browser's TLS handshake.

HTTP/2 messages are reconstructed as HTTP/1.1 with `Fidelity::Reconstructed` and
`HttpProtocol::Http2`. Finalized request headers come from the codec after defaults and removal
of connection-specific fields. Outgoing frames must establish one complete request; an
additional stream or connection fails the capture. Pseudo-headers become the request line,
`host`, or response status. Responses with bodies use generated chunked framing so trailers stay
separate from the initial headers. `HEAD`, `204`, and `304` keep their bodyless form and
representation headers. Binary frames, HPACK state, and original framing declarations are not
stored. The codec also bounds decoded response headers and trailers before reconstruction.

Each fetch owns its client, observer, runtime, and connection. Concurrent fetches cannot share
capture state. For HTTP/1, a codec or write failure invalidates an unfinished capture. An already
complete or truncated response is retained; a later shutdown failure does not invalidate it.

### Dependency patches

The observer hooks are not released upstream. The crate uses a pinned wreq fork and matching TLS
revisions. Cargo does not propagate dependency patches. A consuming workspace that enables `wreq`
must copy these entries into its root manifest, including when using a local path dependency:

```toml
[patch.crates-io]
wreq = { git = "https://github.com/travisbrown/wreq", rev = "108701e00f33b40132e78d28abce8b4f6e3a6b19" }
btls = { git = "https://github.com/0x676e67/btls", rev = "9d859deefab0183e2fccf91204c818c8d1805b27" }
btls-sys = { git = "https://github.com/0x676e67/btls", rev = "9d859deefab0183e2fccf91204c818c8d1805b27" }
tokio-btls = { git = "https://github.com/0x676e67/btls", rev = "9d859deefab0183e2fccf91204c818c8d1805b27" }
```

The manifest pins matching versions of `wreq`, `wreq-proto`, and `wreq-util`. Publication is
disabled while the optional client depends on these patches.

## Development

The `archivindex-http-client/` directory contains the HTTP client crate, its tests, and its
benchmarks. The root manifest defines workspace members, shared package metadata, dependency
versions, lints, and dependency patches. `archivindex-http-client-challenge/` contains the challenge
recognizers, bounded proof solvers, cookie jar, and automatic session. Each additional crate belongs
in its own directory and must be listed in `workspace.members`.

`framing` locates response boundaries and applies limits. `message` parses stored messages;
`body` extracts entity-bodies; `reconstruct` serializes parsed parts into HTTP/1 messages.
Transport setup, request preparation, and error classification stay private.

```sh
cargo +nightly fmt --all -- --check
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo test --workspace --locked --no-default-features
cargo test --workspace --locked --all-features
cargo +1.88.0 check --workspace --locked --all-targets --no-default-features
cargo bench -p archivindex-http-client --locked --bench response_capture -- --test
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --all-features --no-deps
```

All clients run shared conformance and proxy tests against local HTTP, TLS, and SOCKS servers.
Separate suites check exact capture, HTTP/2, and TLS configuration. Tests cover framing across
read boundaries, every cap through chunked trailers, deadlines, disconnects, authentication,
profile overrides, concurrent calls, and calls inside Tokio. The in-memory benchmarks exercise
short responses, long headers, and long chunk extensions at different read sizes.

CI checks both feature configurations on Linux, baseline clients on macOS and Windows, Rust 1.88
compatibility, and fresh compatible dependencies on stable Rust. It also checks formatting,
documentation, and the dependency policy.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
