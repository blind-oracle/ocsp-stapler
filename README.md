# ocsp-stapler

[![crates.io](https://img.shields.io/crates/v/ocsp-stapler.svg)](https://crates.io/crates/ocsp-stapler)
[![Documentation](https://docs.rs/ocsp-stapler/badge.svg)](https://docs.rs/ocsp-stapler)
[![MPL-2 Licensed](https://img.shields.io/crates/l/ocsp-stapler.svg)](./LICENSE)

OCSP stapler for Rustls.

- OCSP `Client` that can be used separately
- `Stapler` wraps `Arc<dyn ResolvesServerCert>` trait object and automatically staples all certificates provided by it

Please see the [docs](https://docs.rs/ocsp-stapler) for more details.

## Example

```rust,ignore
// Read the chain & private key and combine them into CertifiedKey
let certs = std::fs::read("chain.pem").unwrap();
let certs = rustls_pemfile::certs(&mut certs.as_ref()).collect::<Result<Vec<_>, _>>().unwrap();

let key = std::fs::read("private.pem").unwrap();
let key = rustls_pemfile::private_key(&mut key.as_ref()).unwrap();
let key = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();

let ckey = rustls::sign::CertifiedKey::new(certs, key);

// Inner service that provides certificates to Rustls, can be anything
let mut inner = rustls::server::ResolvesServerCertUsingSni::new();
inner.add("crates.io", ckey).unwrap();

// Create a Stapler wrapping inner resolver
let stapler = Arc::new(ocsp_stapler::Stapler::new(inner));

// Then you can build & use ServerConfig wherever applicable
let server_config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(stapler.clone());

// Stop the background worker to clean up resources
stapler.stop().await;
```
