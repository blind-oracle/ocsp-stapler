# ocsp-stapler

[![crates.io](https://img.shields.io/crates/v/ocsp-stapler.svg)](https://crates.io/crates/ocsp-stapler)
[![Documentation](https://docs.rs/ocsp-stapler/badge.svg)](https://docs.rs/ocsp-stapler)
[![MIT/Apache-2 licensed](https://img.shields.io/crates/l/ocsp-stapler.svg)](./LICENSE)

OCSP stapler for Rustls.

- OCSP `Client` that can be used separately
- `Stapler` wraps `Arc<dyn ResolvesServerCert>` trait object and automatically staples all certificates provided by it

`Stapler::new()` spawns background worker using `tokio::spawn` so it must be executed in the Tokio context.

Please see the [docs](https://docs.rs/ocsp-stapler) for more details.

## Example

```rust,ignore
// Inner service that provides certificates to Rustls, can be anything
let ckey: CertifiedKey = ...;
let mut inner = rustls::server::ResolvesServerCertUsingSni::new();
inner.add("crates.io", ckey).unwrap();

let stapler = Arc::new(ocsp_stapler::Stapler::new(inner));

// Then you can build & use server_config wherever applicable
let server_config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(stapler.clone());

// Stop the background worker to clean up
stapler.stop().await;
```
