use std::fmt::Write as _;

use super::{Variance, declared_vary};
use crate::message::{RequestMetadata, ResponseMetadata};

/// Parse a 200 response head carrying `fields`, each written as its own line.
fn response(fields: &[(&str, &str)]) -> ResponseMetadata {
    let mut message = String::from("HTTP/1.1 200 OK\r\n");
    for (name, value) in fields {
        write!(message, "{name}: {value}\r\n").expect("writing to a String cannot fail");
    }
    message.push_str("\r\n");

    ResponseMetadata::parse(message.as_bytes()).expect("a well-formed response head parses")
}

/// Resolve field names against a fixed request.
fn request<'a>(fields: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<&'a str> {
    move |name| {
        fields
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| *value)
    }
}

#[test]
fn a_response_without_vary_declares_none() {
    assert_eq!(declared_vary(&response(&[("ETag", "\"v1\"")])), None);
}

/// A `Vary` sent as several lines selects on every field it names, not just the first line's.
#[test]
fn vary_sent_as_several_lines_is_combined() {
    let metadata = response(&[
        ("Vary", "Accept-Encoding"),
        ("ETag", "\"v1\""),
        ("Vary", "User-Agent"),
    ]);
    let fields = [("accept-encoding", "gzip"), ("user-agent", "Desktop")];

    assert_eq!(
        declared_vary(&metadata).as_deref(),
        Some("Accept-Encoding, User-Agent")
    );
    assert_eq!(
        Variance::declared(declared_vary(&metadata).as_deref(), request(&fields)),
        Variance::declared(Some("Accept-Encoding, User-Agent"), request(&fields))
    );
    assert!(
        !Variance::declared(declared_vary(&metadata).as_deref(), request(&fields)).matches(
            request(&[("accept-encoding", "gzip"), ("user-agent", "Mobile")])
        )
    );
}

/// A selecting field sent as several lines is matched as the one value they combine into.
#[test]
fn a_selecting_field_sent_as_several_lines_is_matched_as_one_value() {
    let sent = RequestMetadata::parse(
        b"GET / HTTP/1.1\r\nAccept-Language: en\r\nAccept-Language: de\r\n\r\n",
    )
    .expect("a well-formed request head parses");
    let variance = Variance::declared(Some("Accept-Language"), |name| sent.combined_header(name));

    assert_eq!(
        variance,
        Variance::declared(
            Some("Accept-Language"),
            request(&[("accept-language", "en, de")])
        )
    );
    assert!(variance.matches(request(&[("accept-language", "en, de")])));
    assert!(!variance.matches(request(&[("accept-language", "en")])));
    assert!(!variance.matches(request(&[("accept-language", "de, en")])));
}

/// A `Vary` line that is not text leaves the representation unselectable.
#[test]
fn vary_that_is_not_text_is_unselectable() {
    let metadata = ResponseMetadata::parse(b"HTTP/1.1 200 OK\r\nVary: \xff\r\n\r\n")
        .expect("a well-formed response head parses");

    assert_eq!(declared_vary(&metadata).as_deref(), Some("*"));
    assert_eq!(
        Variance::declared(declared_vary(&metadata).as_deref(), request(&[])),
        Variance::Unselectable
    );
}

/// A `*` on any line leaves the representation unselectable.
#[test]
fn vary_star_on_a_later_line_is_not_lost() {
    let metadata = response(&[("Vary", "Accept-Encoding"), ("Vary", "*")]);

    assert_eq!(
        Variance::declared(declared_vary(&metadata).as_deref(), request(&[])),
        Variance::Unselectable
    );
}

/// An empty first line does not hide the fields a later line names.
#[test]
fn an_empty_vary_line_does_not_mask_a_later_one() {
    let metadata = response(&[("Vary", ""), ("Vary", "User-Agent")]);

    assert_eq!(declared_vary(&metadata).as_deref(), Some(", User-Agent"));
    assert_eq!(
        Variance::declared_without_request(declared_vary(&metadata).as_deref()),
        Variance::Unselectable
    );
}

#[test]
fn a_response_without_vary_is_invariant() {
    let variance = Variance::declared(None, request(&[("user-agent", "Desktop")]));

    assert_eq!(variance, Variance::Invariant);
    assert!(variance.matches(request(&[("user-agent", "Mobile")])));
}

#[test]
fn a_differing_selecting_field_does_not_match() {
    let variance = Variance::declared(
        Some("User-Agent"),
        request(&[("user-agent", "Desktop"), ("accept", "*/*")]),
    );

    assert!(variance.matches(request(&[("user-agent", "Desktop")])));
    assert!(!variance.matches(request(&[("user-agent", "Mobile")])));
    assert!(!variance.matches(request(&[])));
}

#[test]
fn vary_star_never_matches_even_an_identical_request() {
    let fields = [("user-agent", "Desktop")];
    let variance = Variance::declared(Some("User-Agent, *"), request(&fields));

    assert_eq!(variance, Variance::Unselectable);
    assert!(!variance.matches(request(&fields)));
}

#[test]
fn selecting_fields_are_recorded_independently_of_their_written_form() {
    let fields = [("user-agent", "Desktop"), ("accept-encoding", "gzip")];

    assert_eq!(
        Variance::declared(Some("User-Agent, Accept-Encoding"), request(&fields)),
        Variance::declared(Some("accept-encoding ,USER-AGENT"), request(&fields))
    );
}

#[test]
fn a_response_named_vary_is_unselectable_without_its_request() {
    assert_eq!(
        Variance::declared_without_request(Some("Accept-Encoding")),
        Variance::Unselectable
    );
    assert_eq!(
        Variance::declared_without_request(None),
        Variance::Invariant
    );
}
