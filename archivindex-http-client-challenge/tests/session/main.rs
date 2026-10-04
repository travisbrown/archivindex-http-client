//! Automatic sessions preserve requests, cookies, deadlines, and every completed exchange.

mod limits;
mod scripted;
mod sequences;
#[path = "../support/mod.rs"]
mod support;

use std::time::{Duration, Instant};

use archivindex_http_client::Request;
use archivindex_http_client_challenge::Session;
use http::header::{ACCEPT_ENCODING, CONTENT_TYPE, COOKIE};
use http::{HeaderMap, HeaderValue, Method, Uri};
use scripted::Scripted;
use support::{ISSUED_AT, TRACE_NONCE, captured, simply_body, sucuri_body, varnish_body};

const TARGET: &str = "https://example.com/protected";
const VERIFY: &str = "https://example.com/.sc-verify/";

const fn request<'a>(target: &'a Uri, headers: &'a HeaderMap) -> Request<'a> {
    Request {
        method: &Method::GET,
        target,
        headers,
        body: None,
    }
}

fn sucuri() -> archivindex_http_client::CapturedExchange {
    captured(
        TARGET,
        307,
        &[("x-sucuri-id", "12005")],
        sucuri_body(true).as_bytes(),
    )
}

fn simply() -> archivindex_http_client::CapturedExchange {
    captured(TARGET, 454, &[], simply_body("/.sc-verify/", 4).as_bytes())
}

#[test]
fn sucuri_repeats_the_original_request_and_retains_clearance() {
    let client = Scripted::new([
        Ok(sucuri()),
        Ok(captured(TARGET, 200, &[], b"accepted")),
        Ok(captured(TARGET, 200, &[], b"later")),
    ]);
    let session = Session::new(client.clone());
    let mut headers = HeaderMap::new();
    headers.append(COOKIE, HeaderValue::from_static("session=caller"));
    headers.append(COOKIE, HeaderValue::from_static("preference=dark"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    let target = TARGET.parse().unwrap();
    let original = Request {
        method: &Method::POST,
        body: Some(b"original body"),
        ..request(&target, &headers)
    };
    let exchanges = session.fetch(original).unwrap();
    assert_eq!(exchanges.len(), 2);
    assert_eq!(exchanges[0].response_metadata.status, 307);
    assert_eq!(exchanges[1].entity_body().unwrap(), b"accepted".as_slice());
    session.fetch(request(&target, &HeaderMap::new())).unwrap();

    let sent = client.sent();
    for request in &sent[..2] {
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.target, target);
        assert_eq!(request.body.as_deref(), Some(b"original body".as_slice()));
        assert_eq!(request.headers[CONTENT_TYPE], "text/plain");
        assert_eq!(request.headers.get_all(COOKIE).iter().count(), 1);
        assert_eq!(request.headers[ACCEPT_ENCODING], "identity");
    }
    assert_eq!(sent[0].headers[COOKIE], "session=caller; preference=dark");
    assert_eq!(
        sent[1].headers[COOKIE],
        "session=caller; preference=dark; sucuri_cloudproxy_uuid_test=cookie-value"
    );
    assert_eq!(
        sent[2].headers[COOKIE],
        "sucuri_cloudproxy_uuid_test=cookie-value"
    );
    client.assert_finished();
}

#[test]
fn simply_submits_a_proof_and_preserves_every_exchange_and_the_deadline() {
    let client = Scripted::new([
        Ok(simply()),
        Ok(captured(
            VERIFY,
            200,
            &[],
            br#"{"ok":true,"cookie":"clearance"}"#,
        )),
        Ok(captured(TARGET, 200, &[], b"accepted")),
    ]);
    let session = Session::new(client.clone());
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("user-agent", "Archivindex/1.0"),
        ("accept-language", "en"),
        ("authorization", "Bearer token"),
        ("host", "virtual.example"),
        ("cookie", "session=caller"),
        ("content-type", "application/json"),
        ("content-encoding", "gzip"),
        ("if-none-match", "\"original\""),
        ("range", "bytes=0-10"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    let target = TARGET.parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let exchanges = session
        .fetch_by(request(&target, &headers), deadline)
        .unwrap();
    assert_eq!(
        exchanges
            .iter()
            .map(|exchange| exchange.response_metadata.status)
            .collect::<Vec<_>>(),
        [454, 200, 200]
    );
    assert_eq!(exchanges[1].target_uri.as_str(), VERIFY);

    let sent = client.sent();
    assert!(
        sent.iter()
            .all(|request| request.deadline == Some(deadline))
    );
    assert_eq!(sent[1].method, Method::POST);
    assert_eq!(sent[1].target.to_string(), VERIFY);
    assert_eq!(
        sent[1].headers[CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    for name in [
        "user-agent",
        "accept-language",
        "authorization",
        "host",
        "cookie",
    ] {
        assert_eq!(sent[1].headers[name], headers[name]);
    }
    for name in ["content-encoding", "if-none-match", "range"] {
        assert!(!sent[1].headers.contains_key(name));
        assert_eq!(sent[2].headers[name], headers[name]);
    }
    let fields: Vec<_> = url::form_urlencoded::parse(sent[1].body.as_ref().unwrap()).collect();
    assert_eq!(fields[0], ("ts".into(), ISSUED_AT.into()));
    assert_eq!(fields[1].0, "nonce");
    assert_eq!(fields[2], ("token".into(), support::TOKEN.into()));
    assert_eq!(
        sent[2].headers[COOKIE],
        "session=caller; sc_clearance=clearance"
    );
    client.assert_finished();
}

#[test]
fn varnish_sends_both_trace_and_bypass_cookies() {
    let trace = format!("pow_trace={TRACE_NONCE}|{ISSUED_AT}; path=/");
    let client = Scripted::new([
        Ok(captured(
            TARGET,
            202,
            &[("server", "Varnish"), ("set-cookie", &trace)],
            varnish_body("example.com").as_bytes(),
        )),
        Ok(captured(TARGET, 200, &[], b"accepted")),
    ]);
    let session = Session::new(client.clone());
    session
        .fetch(request(&TARGET.parse().unwrap(), &HeaderMap::new()))
        .unwrap();
    let sent = client.sent();
    let cookie = sent[1].headers[COOKIE].to_str().unwrap();
    assert!(cookie.starts_with(&format!(
        "pow_trace={TRACE_NONCE}|{ISSUED_AT}; pow_bypass={}|",
        support::NONCE
    )));
    client.assert_finished();
}

#[test]
fn supplied_cookies_override_stored_values_and_secure_cookies_stay_on_their_host() {
    let targets = [
        TARGET,
        "http://example.com/protected",
        "https://other.example/protected",
    ];
    let client = Scripted::new(targets.map(|target| {
        Ok(captured(
            target,
            200,
            &[("set-cookie", "ignored=value")],
            b"ok",
        ))
    }));
    let session = Session::new(client.clone());
    session.cookies().insert_header(
        &TARGET.parse().unwrap(),
        HeaderValue::from_static("session=stored; clearance=retained"),
    );
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, HeaderValue::from_static("session=caller"));
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
    session
        .fetch(request(&targets[0].parse().unwrap(), &headers))
        .unwrap();
    for target in &targets[1..] {
        session
            .fetch(request(&target.parse().unwrap(), &HeaderMap::new()))
            .unwrap();
    }
    let sent = client.sent();
    assert_eq!(
        sent[0].headers[COOKIE],
        "session=caller; clearance=retained"
    );
    assert_eq!(sent[0].headers[ACCEPT_ENCODING], "gzip");
    assert!(!sent[1].headers.contains_key(COOKIE));
    assert!(!sent[2].headers.contains_key(COOKIE));
    assert_eq!(
        session.cookies().get(&TARGET.parse().unwrap()).unwrap(),
        "session=stored; clearance=retained"
    );
    client.assert_finished();
}
