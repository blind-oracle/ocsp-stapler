# ocsp-stapler

The `ocsp-stapler` crate provides two structs: `Client` and `Stapler`.

## `Client`
[`client::Client`](client) is an OCSP client that can be used to query the OCSP responders of the Certificate Authorities. It tries to mostly conform to the [lightweight OCSP profile](https://datatracker.ietf.org/doc/html/rfc5019)

- Currently only SHA-1 digest for OCSP request is supported since it's the only one that LetsEncrypt uses
- Requests <= 255 bytes will be sent using GET and Base64, otherwise POST

## `Stapler`
[`stapler::Stapler`](stapler) uses [`client::Client`](client) internally and provides a Rustls-compatible API to attach (staple) OCSP responses to the certificates.

It wraps whatever that implements Rustls' [`rustls::server::ResolvesServerCert`](https://docs.rs/rustls/latest/rustls/server/trait.ResolvesServerCert.html) trait and also implements the same trait itself.

The workflow is the following:
- [`stapler::Stapler`](stapler) receives a `ClientHello` from Rustls and forwards it to the wrapped resolver to retrieve the certificate chain
- It calculates the SHA-1 fingerprint over the whole end-entity certificate and uses that to check if it has the same certificate
in the local storage:
    - If not, then it sends the certificate to the background worker for eventual processing & stapling.
Meanwhilte it returns to Rustls the original unstapled certificate
    - If found, it responds with a stapled version of the certificate

Since the certificates are only stapled eventually then the `Must-Staple` marked certificates will not work out of the box - first request for them will always be failed by the client. Maybe later an API to pre-staple them will be added.

Background worker duties:
- Receieves the certificates from `Stapler`, processes them and inserts into the local storage
- Wakes up every minute (or when a new certificate is added) to do the following:
- Obtain OCSP responses for newly added certificates
- Renew the OCSP responses that are already past 50% of their validity interval
- Check for expired certificates & purge them
- Check for expired OCSP responses and clear them
- Post an updated version of storage that is shared with `Stapler`

Background worker is spawned by `Stapler::new()` using `tokio::spawn` so it must be executed in Tokio context.
It runs indefinitely unless stopped with `Stapler::stop()`.

Other notes:
- Stapler does not check the certificate validity (i.e. does not traverse the chain up to the root)
- Certificates without the issuer's certificate are passed through as-is since we can't query the OCSP without access to the issuer's public key

### Metrics

Stapler supports a few Prometheus metrics - create it using one of `new_..._with_registry()` constructors and provide a Prometheus `Registry` reference to register the metrics in.

### Example

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
