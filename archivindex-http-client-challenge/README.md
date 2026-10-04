# archivindex-http-client-challenge

HTTP challenge handling extracted from `archivindex-warc`. A `Session` wraps any
`archivindex_http_client::Client`, answers recognized challenges, and retains clearance cookies
for later requests. Every exchange is returned in request order, including the challenge page
and any proof verification response.

| Challenge  | Recognition                                 | Answer                                                |
| ---------- | ------------------------------------------- | ----------------------------------------------------- |
| Sucuri     | `307` with `x-sucuri-id` and its script     | Decode the script's cookie                            |
| Varnish    | `202` with `Server: Varnish` and proof data | Solve a SHA-256 prefix, send trace and bypass cookies |
| Simply.com | `454` with its token and proof data         | Solve a SHA-256 prefix, POST for clearance            |

The recognizers read a limited set of script expressions without executing JavaScript.
Unrecognized, malformed, unsupported, or truncated challenges end the sequence with the captured
response intact. Redirect following is opt-in. Sessions do not retry transport failures.

## Usage

```rust,no_run
use std::time::{Duration, Instant};

use archivindex_http_client::recorder::Recorder;
use archivindex_http_client::Request;
use archivindex_http_client_challenge::Session;
use http::{HeaderMap, Method};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = Session::new(Recorder::new());
    let result = session.fetch_by(
        Request {
            method: &Method::GET,
            target: &"https://example.com/".parse()?,
            headers: &HeaderMap::new(),
            body: None,
        },
        Instant::now() + Duration::from_secs(30),
    );

    let exchanges = match result {
        Ok(exchanges) => exchanges,
        Err(error) => {
            eprintln!("{}", error.source);
            error.exchanges
        }
    };
    for exchange in exchanges {
        println!("{} {}", exchange.target_uri, exchange.response_metadata.status);
    }
    Ok(())
}
```

Reuse the session to reuse its cookies. `fetch` applies only the underlying client's timeouts;
`fetch_by` and `fetch_within` pass one deadline through every request and proof search. Calls are
synchronous. Cloned sessions share cookies and can fetch concurrently. Clients with the optional
`wreq` feature work the same way.

Success means the sequence finished. It does not imply that clearance was granted: the final
exchange can still be a challenge or a rejected verification. A failure returns all exchanges
completed before the error in `Error::exchanges`. Captures keep the underlying client's fidelity,
protocol, timing, and truncation metadata.

## Requests and limits

A fetch answers at most three challenges (`MAX_CHALLENGE_ANSWERS`). Challenge retries preserve
the original method and body, including for POST requests. Simply.com verification uses a separate
form POST to `/.sc-verify/` on the challenged origin. It preserves the original `User-Agent`,
`Accept-Language`, `Authorization`, `Proxy-Authorization`, `Host`, and `Cookie` fields. The original
request's body metadata, validators, and range headers are not sent with the proof.

Proof searches try at most ten million candidates and check the deadline every 256 attempts.
Varnish difficulty is capped at five hexadecimal digits; Simply.com difficulty is capped at 20
leading zero bits. These bounds limit work but do not guarantee a solution. A deadline that
expires during solving returns an error with the challenge capture retained. A response the client
already marked as truncated is returned without further work.

Sessions supply `Accept-Encoding: identity` unless the request specifies its own value.
Recognition removes transfer coding but does not decompress content. A server that sends compressed
content cannot be answered by these recognizers.

## Redirects and request hooks

Set `max_redirects(n)` to follow at most `n` redirects. The default is zero. Redirects and challenge
answers have separate counters, and neither resets the overall deadline. A redirect within one
origin retains caller-supplied authority headers. A redirect to another origin removes `Host`,
`Authorization`, `Proxy-Authorization`, and `Cookie`. POST changes to GET after 301, 302, or 303;
303 also changes other methods except HEAD. A method change removes the body and its framing fields.
Unusable locations and redirects past the limit end the sequence with the response retained.

`fetch_with(request, deadline, observer)` allows preparation after cookies have been resolved and
observes each completed exchange before the next request. Its return value counts followed
redirects. An `Observer` can add conditional headers for the selected representation and retain
application metadata with each exchange. `RequestKind::Verification` distinguishes proof submission
from resource requests so representation validators can be omitted. Preparation failures stop the
sequence; all earlier exchanges have already been delivered to the observer. Ordinary `fetch`
methods use the same loop and collect those exchanges automatically.

## Cookies

`Session::cookies()` locks the jar for inspection or preloading. Release the guard before fetching.
`CookieJar::insert_for(url, cookie)` validates supplied cookie values and rejects URLs carrying
credentials. Use `with_cookies` to share an existing `Arc<Mutex<CookieJar>>` across sessions.
The session never holds this lock during network requests or observer callbacks. Cookies are
scoped to the exact host. Secure cookies are withheld from HTTP, and cookies preloaded for an
HTTPS URL are also restricted to HTTPS. Explicit request cookies take precedence over stored
cookies of the same name; remaining stored cookies are appended. Multiple `Cookie` fields are
combined into one field before sending.

The jar retains supplied and challenge cookies only. It does not process ordinary `Set-Cookie`
responses or implement path, expiry, or `Domain` matching.

## Manual handling

`recognize(&captured, deadline)` returns either `Challenge::Cookie` or `Challenge::ProofOfWork`.
Callers managing their own loop can store the cookie, or submit `ProofOfWork::request_body()` to
`verification_url()` and read the result with `clearance_cookie()`. Verification must be complete,
have status `200`, and belong to the proof's verification URL. Manual loops must bound repeated
answers themselves and retain any exchanges they need.

## License

GPL-3.0-only. See [LICENSE](../LICENSE).
