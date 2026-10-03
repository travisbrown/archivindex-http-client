# archivindex-http-client

![GitHub last commit][last-commit-badge]
[![build][build-badge]][build]
[![license][license-badge]][gpl-3.0]

A Rust library of HTTP clients that capture the request and response messages of each exchange,
for the [Archivindex][archivindex] projects. It can store the exact bytes of an HTTP/1.1 exchange,
and it can reconstruct the messages of exchanges made with [`reqwest`][reqwest] or, behind the
`wreq` feature, with [`wreq`][wreq] and its browser emulation (including HTTP/2, which is opt-in).

See the [crate README](crates/http-client/README.md) for the backends, their capture
contracts, and usage examples.

## Repository

The workspace has one package, [`archivindex-http-client`](crates/http-client/). Its `wreq` feature
depends on a `wreq` fork and on unreleased `btls` revisions, which the
[workspace manifest](Cargo.toml) declares as patches.

## Development

The workspace requires Rust 1.88 or later. The `wreq` feature requires Rust 1.98 and a native
BoringSSL toolchain: a C and C++ compiler, CMake, and libclang.

Run the tests and build the documentation with:

```console
cargo test --locked
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
```

Add `--features wreq` to either command to include the `wreq` backend. The remaining checks that CI
runs are:

```console
cargo +nightly fmt --all -- --check
cargo clippy --locked --all-targets --features wreq -- -D warnings
taplo fmt --check --diff
taplo lint
rumdl check .
cargo deny --workspace check
cargo archivindex-build check
```

## License

This project is licensed under the [GNU General Public License, version 3][gpl-3.0]; see
[LICENSE](LICENSE) for the full text.

[archivindex]: https://github.com/travisbrown/archivindex
[build]: https://github.com/travisbrown/archivindex-http-client/actions/workflows/ci.yml
[build-badge]: https://github.com/travisbrown/archivindex-http-client/actions/workflows/ci.yml/badge.svg
[gpl-3.0]: https://www.gnu.org/licenses/gpl-3.0.html
[last-commit-badge]: https://img.shields.io/github/last-commit/travisbrown/archivindex-http-client
[license-badge]: https://img.shields.io/badge/license-GPL--v3-blue
[reqwest]: https://crates.io/crates/reqwest
[wreq]: https://crates.io/crates/wreq
