# ocsp-stapler

[![crates.io](https://img.shields.io/crates/v/ocsp-stapler.svg)](https://crates.io/crates/ocsp-stapler)
[![Documentation](https://docs.rs/ocsp-stapler/badge.svg)](https://docs.rs/ocsp-stapler)
[![MIT/Apache-2 licensed](https://img.shields.io/crates/l/ocsp-stapler.svg)](./LICENSE)

OCSP stapler for Rustls.

- Standalone `Client` that can be used separately
- `Stapler` wraps `Arc<dyn ResolvesServerCert>` trait object and automatically staples all certificates provided by it

`Stapler::new()` spawns background worker using `tokio::spawn` so it must be executed in the Tokio context.

## Example

```rust,no_run
// Inner service that provides certificates to Rustls, can be anything
let inner: Arc<dyn ResolvesCerverCert> = ...;

let stapler = Arc::new(ocsp_stapler::Stapler::new(inner));

let server_config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(stapler.clone());

// Then you can use server_config wherever applicable

// Stop the background worker to clean up
stapler.stop().await;
```
