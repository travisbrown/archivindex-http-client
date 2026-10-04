//! Recognition uses captured HTTP messages and validates the protocol before deriving an answer.

mod support;

use std::time::Instant;

use archivindex_http_client::framing::Truncation;
use archivindex_http_client_challenge::{Challenge, recognize};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use support::{
    ISSUED_AT, NONCE, TOKEN, TRACE_NONCE, captured, simply_body, sucuri_body, varnish_body,
};

#[test]
fn sucuri_recovers_the_cookie_and_its_secure_attribute() {
    for secure in [false, true] {
        let response = captured(
            "https://example.com/path",
            307,
            &[("x-sucuri-id", "12005")],
            sucuri_body(secure).as_bytes(),
        );
        let Some(Challenge::Cookie(cookie)) = recognize(&response, None) else {
            panic!("a Sucuri cookie");
        };
        assert_eq!(cookie.value, "sucuri_cloudproxy_uuid_test=cookie-value");
        assert_eq!(cookie.secure, secure);
    }
}

#[test]
fn simply_solves_and_validates_the_verification_response() {
    for scheme in ["http", "https"] {
        let response = captured(
            &format!("{scheme}://example.com/protected"),
            454,
            &[("server", "cloudflare")],
            simply_body("/.sc-verify/", 4).as_bytes(),
        );
        let Some(Challenge::ProofOfWork(proof)) = recognize(&response, None) else {
            panic!("a solved Simply.com challenge");
        };
        assert_eq!(
            proof.verification_url().as_str(),
            format!("{scheme}://example.com/.sc-verify/")
        );
        let body = proof.request_body();
        let fields: Vec<_> = url::form_urlencoded::parse(body.as_bytes()).collect();
        assert_eq!(fields[0], ("ts".into(), ISSUED_AT.into()));
        assert_eq!(fields[1].0, "nonce");
        assert_eq!(fields[2], ("token".into(), TOKEN.into()));
        let digest = Sha256::digest(format!("{TOKEN}:{}", fields[1].1));
        assert!(digest[0].leading_zeros() >= 4);

        let verification = captured(
            proof.verification_url().as_str(),
            200,
            &[],
            br#"{"ok":true,"cookie":"clearance-value"}"#,
        );
        let cookie = proof.clearance_cookie(&verification).unwrap();
        assert_eq!(cookie.value, "sc_clearance=clearance-value");
        assert_eq!(cookie.secure, scheme == "https");

        for (status, body) in [
            (403, br#"{"ok":true,"cookie":"value"}"#.as_slice()),
            (200, br#"{"ok":false,"cookie":"value"}"#),
            (200, br#"{"ok":true,"cookie":""}"#),
            (200, br#"{"ok":true,"cookie":"value; other=injected"}"#),
            (200, br#"{"ok":true,"cookie":"value,other"}"#),
            (200, br#"{"ok":true,"cookie":"value\r\n"}"#),
            (200, b"not json"),
        ] {
            let rejected = captured(proof.verification_url().as_str(), status, &[], body);
            assert!(proof.clearance_cookie(&rejected).is_none());
        }
        let mut truncated = verification.clone();
        truncated.truncated = Some(Truncation::Length);
        assert!(proof.clearance_cookie(&truncated).is_none());
        let mut unrelated = verification;
        unrelated.target_uri = "https://elsewhere.example/.sc-verify/".parse().unwrap();
        assert!(proof.clearance_cookie(&unrelated).is_none());
    }
}

#[test]
fn simply_rejects_unsafe_endpoints_and_excessive_difficulty() {
    for path in [
        "https://elsewhere.example/.sc-verify/",
        "//elsewhere.example/.sc-verify/",
        "http://example.com/.sc-verify/",
        "https://user:secret@example.com/.sc-verify/",
        "/other-path",
        "/.sc-verify/?extra=1",
        "/.sc-verify/#fragment",
    ] {
        let response = captured(
            "https://example.com/",
            454,
            &[],
            simply_body(path, 0).as_bytes(),
        );
        assert!(recognize(&response, None).is_none(), "{path}");
    }
    let response = captured(
        "https://example.com/",
        454,
        &[],
        simply_body("/.sc-verify/", 21).as_bytes(),
    );
    assert!(recognize(&response, None).is_none());
}

#[test]
fn varnish_keeps_the_renewed_trace_and_computes_a_valid_bypass() {
    let trace = format!("pow_trace={TRACE_NONCE}|{ISSUED_AT}; path=/");
    let response = captured(
        "https://www.example.com/path",
        202,
        &[
            ("server", "Varnish"),
            ("set-cookie", "unrelated=value; path=/"),
            ("set-cookie", &trace),
        ],
        varnish_body(".EXAMPLE.com").as_bytes(),
    );
    let Some(Challenge::Cookie(cookie)) = recognize(&response, None) else {
        panic!("Varnish trace and bypass cookies");
    };
    let expected_trace = format!("pow_trace={TRACE_NONCE}|{ISSUED_AT}; pow_bypass=");
    let fields: Vec<_> = cookie
        .value
        .to_str()
        .unwrap()
        .strip_prefix(&expected_trace)
        .unwrap()
        .split('|')
        .collect();
    assert_eq!(fields.len(), 5);
    assert_eq!(fields[0], NONCE);
    assert_eq!(fields[1], ISSUED_AT);
    assert_eq!(
        fields[3],
        HEXLOWER.encode(&Sha256::digest(format!("{NONCE}{ISSUED_AT}{}", fields[2])))
    );
    assert!(fields[3].starts_with('b'));
    assert_eq!(fields[4], "22d6f9feb179b6b7e9616ede");
    assert!(cookie.secure);
}

#[test]
fn varnish_rejects_unrelated_domains_bad_traces_and_excessive_work() {
    for (domain, trace, difficulty) in [
        (
            "elsewhere.example",
            format!("pow_trace={TRACE_NONCE}|{ISSUED_AT}"),
            "1",
        ),
        (
            "ample.com",
            format!("pow_trace={TRACE_NONCE}|{ISSUED_AT}"),
            "1",
        ),
        ("example.com", format!("pow_trace={TRACE_NONCE}|0"), "1"),
        (
            "example.com",
            format!("pow_trace={TRACE_NONCE}|{ISSUED_AT}|extra"),
            "1",
        ),
        ("example.com", "pow_trace=invalid".to_owned(), "1"),
        (
            "example.com",
            format!("pow_trace={TRACE_NONCE}|{ISSUED_AT}"),
            "6",
        ),
    ] {
        let body =
            varnish_body(domain).replace("difficulty:'1'", &format!("difficulty:'{difficulty}'"));
        let response = captured(
            "https://example.com/",
            202,
            &[("server", "Varnish"), ("set-cookie", &trace)],
            body.as_bytes(),
        );
        assert!(recognize(&response, None).is_none());
    }
}

#[test]
fn unrecognized_and_truncated_responses_and_expired_deadlines_have_no_answer() {
    let body = sucuri_body(false);
    for (status, fields) in [(200, vec![("x-sucuri-id", "12005")]), (307, vec![])] {
        assert!(
            recognize(
                &captured("http://example.com/", status, &fields, body.as_bytes()),
                None
            )
            .is_none()
        );
    }
    let mut response = captured(
        "http://example.com/",
        307,
        &[("x-sucuri-id", "12005")],
        body.as_bytes(),
    );
    assert!(recognize(&response, Some(Instant::now())).is_none());
    for reason in [Truncation::Length, Truncation::Time, Truncation::Disconnect] {
        response.truncated = Some(reason);
        assert!(recognize(&response, None).is_none());
    }
}
