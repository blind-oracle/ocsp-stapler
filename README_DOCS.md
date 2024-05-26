# ocsp-stapler

The `ocsp-stapler` crate provides the following main structs:

## [`Client`](client::Client)
[`Client`](client::Client) is an OCSP client that can be used to query the OCSP responders of the Certificate Authorities. It tries to mostly conform to the [lightweight OCSP profile](https://datatracker.ietf.org/doc/html/rfc5019) that LetsEncrypt uses.

- Currently only SHA-1 digest for OCSP request is supported
- Requests <= 255 bytes will be sent using GET and Base64, otherwise POST

## [`Stapler`](stapler::Stapler)
[`Stapler`](stapler::Stapler) uses [`Client`](client::Client) internally and provides a Rustls-compatible API to attach (staple) OCSP responses to the certificates.

It wraps anything that implements [`ResolvesServerCert`](rustls::server::ResolvesServerCert) and also implements the same trait itself.

The workflow is the following:
- [`Stapler`](stapler::Stapler) receives a [`ClientHello`](rustls::server::ClientHello) from Rustls and forwards it to the wrapped resolver to retrieve the certificate chain
- It calculates the SHA-1 fingerprint over the whole end-entity certificate and uses that to check if it has the same certificate
in the local storage:
    - If not, then it sends the certificate to the background worker for eventual processing & stapling. Meanwhilte it returns to Rustls the original unstapled certificate
    - If found, it responds with a stapled version of the certificate

Since the certificates are only stapled eventually then the `Must-Staple` marked certificates will not work out of the box - first request for them will always be failed by the client. In this case you can use [`Stapler::preload`](stapler::Stapler::preload) to pre-staple the certificate and [`Stapler::status`](stapler::Stapler::status) to check if the stapling was done.

Background worker duties:
- Receieves the certificates from [`Stapler`](stapler::Stapler), processes them and inserts into the local storage
- Wakes up every minute (or when a new certificate is added) to do the following:
    - Obtain OCSP responses for the newly added certificates if any
    - Renew the OCSP responses that are already past 50% of their validity interval
    - Check for expired certificates & purge them
    - Check for expired OCSP responses and clear them. This is needed to make sure we don't serve expired OCSP responses for whatever reason (e.g. OCSP responder might return us stale results etc)
    - Post an updated version of storage that is shared with [`Stapler`](stapler::Stapler)

Background worker is spawned by [`Stapler::new`](stapler::Stapler::new) using `tokio::spawn` so it must be executed in Tokio context.
It runs indefinitely unless stopped with [`Stapler::stop`](stapler::Stapler::stop).

Other notes:
- Stapler does not check the certificate chain (i.e. does not traverse the chain up to the root), it only checks that current time fits in its validity period. If it's not valid - we don't try staple it and pass through as-is.

- Certificates without the issuers (i.e. when [`CertifiedKey`](rustls::sign::CertifiedKey) contains only single end-entity certificate) are passed through as-is since we can't query the OCSP without access to the issuer's public key.

### Metrics

Stapler supports a few Prometheus metrics - create it using one of `new_..._with_registry()` constructors and provide a Prometheus [`Registry`](prometheus::Registry) reference to register the metrics in.

### Example

```rust,ignore
// Read the chain & private key and combine them into CertifiedKey
let certs = std::fs::read("chain.pem").unwrap();
let certs = rustls_pemfile::certs(&mut certs.as_ref()).collect::<Result<Vec<_>, _>>().unwrap();

let key = std::fs::read("private.pem").unwrap();
let key = rustls_pemfile::private_key(&mut key.as_ref()).unwrap();
let key = aws_lc_rs::sign::any_supported_type(&key).unwrap();

let ckey = CertifiedKey::new(certs, key);

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
