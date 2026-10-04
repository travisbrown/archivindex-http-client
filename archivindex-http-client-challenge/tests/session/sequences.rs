use std::sync::{Arc, Condvar, Mutex};

use archivindex_http_client::{CapturedExchange, Client, Error, Request};
use archivindex_http_client_challenge::{FetchError, Observer, RequestKind};
use http::header::{AUTHORIZATION, HOST, IF_NONE_MATCH};

use super::*;

#[derive(Default)]
struct Observed {
    cookies: Arc<Mutex<archivindex_http_client_challenge::cookies::CookieJar>>,
    exchanges: Vec<CapturedExchange>,
    kinds: Vec<RequestKind>,
    fail_after: Option<usize>,
}

impl Observer for Observed {
    type Error = &'static str;

    fn prepare(
        &mut self,
        _: &Method,
        _: &Uri,
        headers: &mut HeaderMap,
        kind: RequestKind,
    ) -> Result<(), Self::Error> {
        assert!(
            self.cookies.try_lock().is_ok(),
            "preparation must not hold the jar lock"
        );
        if self.fail_after == Some(self.exchanges.len()) {
            return Err("refused");
        }
        self.kinds.push(kind);
        // An original representation is selected only until clearance changes the Cookie field.
        if kind == RequestKind::Resource && !headers.contains_key(COOKIE) {
            headers.insert(
                IF_NONE_MATCH,
                HeaderValue::from_static("\"before-clearance\""),
            );
        }
        Ok(())
    }

    fn captured(&mut self, exchange: CapturedExchange, _: &Method) {
        assert!(
            self.cookies.try_lock().is_ok(),
            "observation must not hold the jar lock"
        );
        self.exchanges.push(exchange);
    }
}

#[test]
fn hooks_resolve_clearance_before_validators_and_skip_verification() {
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
    let mut observed = Observed::default();
    let session = Session::new(client.clone()).with_cookies(Arc::clone(&observed.cookies));
    let redirects = session
        .fetch_with(
            request(&TARGET.parse().unwrap(), &HeaderMap::new()),
            None,
            &mut observed,
        )
        .unwrap();
    assert_eq!(redirects, 0);
    assert_eq!(observed.exchanges.len(), 3);
    assert_eq!(
        observed.kinds,
        [
            RequestKind::Resource,
            RequestKind::Verification,
            RequestKind::Resource
        ]
    );
    let sent = client.sent();
    assert!(sent[0].headers.contains_key(IF_NONE_MATCH));
    assert!(!sent[1].headers.contains_key(IF_NONE_MATCH));
    assert!(!sent[2].headers.contains_key(IF_NONE_MATCH));
    assert!(sent[2].headers.contains_key(COOKIE));
}

#[test]
fn preparation_failure_retains_prior_exchanges_and_prevents_the_next_request() {
    let client = Scripted::new([Ok(captured(TARGET, 302, &[("location", "/next")], b""))]);
    let mut observed = Observed {
        fail_after: Some(1),
        ..Observed::default()
    };
    let session = Session::new(client.clone())
        .max_redirects(1)
        .with_cookies(Arc::clone(&observed.cookies));
    let error = session
        .fetch_with(
            request(&TARGET.parse().unwrap(), &HeaderMap::new()),
            None,
            &mut observed,
        )
        .unwrap_err();
    assert!(matches!(error, FetchError::Observer("refused")));
    assert_eq!(observed.exchanges.len(), 1);
    assert_eq!(client.sent().len(), 1);
}

#[test]
fn redirects_share_one_challenge_budget_and_deadline() {
    let targets = [
        TARGET,
        "https://example.com/two",
        "https://example.com/three",
        "https://example.com/four",
    ];
    let mut replies = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        replies.push(Ok(captured(
            target,
            307,
            &[("x-sucuri-id", "12005")],
            sucuri_body(true).as_bytes(),
        )));
        if let Some(next) = targets.get(index + 1) {
            replies.push(Ok(captured(target, 302, &[("location", next)], b"")));
        }
    }
    let client = Scripted::new(replies);
    let session = Session::new(client.clone()).max_redirects(3);
    let deadline = Instant::now() + Duration::from_secs(5);
    let exchanges = session
        .fetch_by(
            request(&TARGET.parse().unwrap(), &HeaderMap::new()),
            deadline,
        )
        .unwrap();
    assert_eq!(exchanges.len(), 7);
    assert_eq!(exchanges.last().unwrap().response_metadata.status, 307);
    assert!(
        client
            .sent()
            .iter()
            .all(|sent| sent.deadline == Some(deadline))
    );
    client.assert_finished();
}

#[test]
fn cross_origin_redirects_drop_credentials_and_rewrite_post_bodies() {
    let next = "https://other.example/next";
    let client = Scripted::new([
        Ok(captured(TARGET, 303, &[("location", next)], b"")),
        Ok(captured(next, 200, &[], b"accepted")),
    ]);
    let session = Session::new(client.clone()).max_redirects(1);
    let mut headers = HeaderMap::new();
    for (name, value) in [
        (AUTHORIZATION, "Bearer secret"),
        (COOKIE, "session=secret"),
        (HOST, "virtual.example"),
        (CONTENT_TYPE, "text/plain"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    session
        .fetch(Request {
            method: &Method::POST,
            target: &TARGET.parse().unwrap(),
            headers: &headers,
            body: Some(b"body"),
        })
        .unwrap();
    let sent = client.sent();
    assert_eq!(sent[1].method, Method::GET);
    assert_eq!(sent[1].body, None);
    for name in [AUTHORIZATION, COOKIE, HOST, CONTENT_TYPE] {
        assert!(!sent[1].headers.contains_key(name));
    }
}

#[derive(Clone, Debug, Default)]
struct Concurrent {
    arrivals: Arc<(Mutex<usize>, Condvar)>,
}

impl Client for Concurrent {
    fn fetch_within(
        &self,
        request: Request<'_>,
        _: Option<Instant>,
    ) -> Result<CapturedExchange, Error> {
        let (count, ready) = &*self.arrivals;
        let timed = {
            let mut arrivals = count.lock().unwrap();
            *arrivals += 1;
            ready.notify_all();
            ready
                .wait_timeout_while(arrivals, Duration::from_secs(3), |count| *count < 2)
                .unwrap()
                .1
        };
        assert!(
            !timed.timed_out(),
            "shared cookies must not serialize network calls"
        );
        assert_eq!(request.headers[COOKIE], "shared=value");
        Ok(captured(TARGET, 200, &[], b"accepted"))
    }
}

#[test]
fn cloned_sessions_share_cookies_without_serializing_network_calls() {
    let session = Session::new(Concurrent::default());
    session
        .cookies()
        .insert_for(TARGET, "shared=value")
        .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let session = session.clone();
            scope.spawn(move || {
                session
                    .fetch(request(&TARGET.parse().unwrap(), &HeaderMap::new()))
                    .unwrap()
            });
        }
    });
}

#[test]
fn cookie_validation_rejects_credentials_and_injection_without_echoing_values() {
    let mut jar = archivindex_http_client_challenge::cookies::CookieJar::default();
    let error = jar
        .insert_for("https://user:secret@example.com/", "a=b")
        .unwrap_err();
    assert!(!error.to_string().contains("secret"));
    let error = jar
        .insert_for(TARGET, "a=secret\r\nx: injected")
        .unwrap_err();
    assert!(!error.to_string().contains("secret"));
    assert!(jar.get(&TARGET.parse().unwrap()).is_none());
}
