#![warn(clippy::all)]
#![warn(clippy::nursery)]

//! # ocsp-stapler
//!
//! The `ocsp-stapler` crate provides two structs: `Client` and `Stapler`.
//!
//! ## `Client`
//! `Client` is an OCSP client that you can use to do OCSP requests to OCSP responders of the Certificate Authorities.
//!
//! ## `Stapler`
//! `Stapler` uses `Client` internally and provides a Rustls-compatible API to attach (staple) OCSP responses to the certificates.
//! It wraps whatever that implements Rustls' `ResolvesServerCert` trait and also implements the same trait.
//!
//! The workflow is the following:
//! - `Stapler` receives a `ClientHello` from Rustls and forwards it to ther wrapped trait object to get the certificate chain
//! - It calculates the SHA-1 fingerprint over the whole end-entity certificate and uses that to check if it has the same certificate
//!   in the local storage
//! - If not - it sends the certificate to the background worker for eventual processing & stapling.
//!   Meanwhilte it returns to Rustls the original unstapled certificate
//! - If found - it respondes with a stapled version of the certificate
//!
//! Background worker duties:
//! - Receieves the certificates from `Stapler`, processes them and inserts into the local storage
//! - Wakes up every 60s (or when a new certificate is added) to do the following:
//!   - Renew the OCSP responses that are already past 50% of their validity interval
//!   - Check for expired certificates & purge them
//!   - Check for expired OCSP responses and clear them
//!   - Post an updated version of storage that is shared with `Stapler`
//!
//! Background worker is spawned by `Stapler::new()` using `tokio::spawn` so it must be executed in Tokio context.
//! It runs indefinitely unless stopped with `Stapler.stop()`.
//!
//! # Example
//!
//! ```rust,ignore
//! // Inner service that provides certificates to Rustls, can be anything
//! let ckey: CertifiedKey = ...;
//! let mut inner = rustls::server::ResolvesServerCertUsingSni::new();
//! inner.add("crates.io", ckey).unwrap();
//!
//! let stapler = Arc::new(ocsp_stapler::Stapler::new(inner));
//!
//! let server_config = rustls::server::ServerConfig::builder()
//!         .with_no_client_auth()
//!         .with_cert_resolver(stapler.clone());
//!
//! // Then you can use server_config wherever applicable
//!
//! // Stop the background worker to clean up
//! stapler.stop().await;
//! ```

pub mod client;
pub mod stapler;

pub use client::Client;
pub use stapler::Stapler;

use chrono::{DateTime, FixedOffset};

/// OCSP response validity interval
#[derive(Clone)]
pub struct OcspValidity {
    pub this_update: DateTime<FixedOffset>,
    pub next_update: DateTime<FixedOffset>,
}

impl OcspValidity {
    // Check if we're already past the half of this validity duration
    pub fn time_to_update(&self, now: DateTime<FixedOffset>) -> bool {
        now >= self.this_update + ((self.next_update - self.this_update) / 2)
    }
}
