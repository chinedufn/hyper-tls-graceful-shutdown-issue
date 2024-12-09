# hyper TLS graceful shutdown issue

hyper issue: https://github.com/hyperium/hyper/issues/3792

This repository aims to demonate an issue with gracefully shutting down a [`hyper`] server
when it uses Transport Layer Security (TLS).

The repository contains two test cases.
In both test cases we start a server, send many concurrent requests to it, and then initiate a graceful shutdown while
those requests are still in-progress.

In the first test case, we do not use TLS. This test case always passes.

We use TLS in the second test case. This test case always fails.

```sh
# This always passes
cargo test -- graceful_shutdown_without_tls

# This always fails
cargo test -- graceful_shutdown_with_tls
```

Example error:

```text
Error during the request/response cycle:
error sending request for url (https://127.0.0.1:62103/)
reqwest::Error { kind: Request, url: "https://127.0.0.1:62103/", source: hyper_util::client::legacy::Error(SendRequest, hyper::Error(IncompleteMessage)) }
thread 'tests::graceful_shutdown_with_tls' panicked at src/lib.rs:310:25:
```

Issue was reproduced on:

```text
MacBook Pro 16-inch, 2019
2.4 GHz 8-Core Intel Core i9
```

## Tracing

Here's how to run the failing test with tracing:

```sh
RUST_LOG="hyper_graceful_shutdown_issue=trace,hyper=trace,hyper_util=trace" RUSTFLAGS='--cfg hyper_unstable_tracing' cargo test --features hyper-tracing -- graceful_shutdown_with_tls
```

[`hyper`]: https://github.com/hyperium/hyper
