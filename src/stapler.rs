use std::{
    collections::BTreeMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use chrono::{DateTime, FixedOffset, TimeDelta, Utc};
use rasn_ocsp::CertStatus;
use rustls::{
    pki_types::CertificateDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha1::{Digest, Sha1};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::warn;
use x509_parser::prelude::*;

use super::{client::Client, OcspValidity};

type Storage = BTreeMap<Fingerprint, Cert>;

// Uniquely identifies the certificate, contains SHA-1 of the whole certificate body
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Fingerprint([u8; 20]);

impl From<&CertificateDer<'_>> for Fingerprint {
    fn from(v: &CertificateDer) -> Self {
        let digest = Sha1::digest(v.as_ref());
        Self(digest.into())
    }
}

#[derive(Clone)]
struct Cert {
    ckey: Arc<CertifiedKey>,
    cert_validity: DateTime<FixedOffset>,
    ocsp_validity: Option<OcspValidity>,
}

pub struct Stapler {
    tx: mpsc::Sender<(Fingerprint, Arc<CertifiedKey>)>,
    storage: Arc<ArcSwapOption<Storage>>,
    inner: Arc<dyn ResolvesServerCert>,
    tracker: TaskTracker,
    token: CancellationToken,
}

impl Stapler {
    /// Creates a Stapler with a provided OCSP Client
    pub fn new_with_client(inner: Arc<dyn ResolvesServerCert>, client: Client) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        let storage = Arc::new(ArcSwapOption::empty());
        let tracker = TaskTracker::new();
        let token = CancellationToken::new();

        let mut actor = StaplerActor {
            client,
            storage: BTreeMap::new(),
            rx,
            published: storage.clone(),
        };

        // Spawn the background task
        let actor_token = token.clone();
        tracker.spawn(async move {
            actor.run(actor_token).await;
        });

        Self {
            tx,
            storage,
            inner,
            tracker,
            token,
        }
    }

    /// Creates a Stapler with a default OCSP Client
    pub fn new(inner: Arc<dyn ResolvesServerCert>) -> Self {
        Self::new_with_client(inner, Client::new())
    }

    /// Tells the background worker to stop and waits until it does
    pub async fn stop(&self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

/// Debug is required for ResolvesServerCert trait
impl fmt::Debug for Stapler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OcspStapler")
    }
}

impl ResolvesServerCert for Stapler {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Try to get the cert from the inner resolver
        let ckey = self.inner.resolve(client_hello)?;

        // Check that we have at least two certificates in the chain.
        // Otherwise we can't staple it since we need an issuer certificate too.
        // In this case just return it back unstapled.
        if ckey.cert.len() < 2 {
            return Some(ckey);
        }

        // Compute the fingerprint
        let fp = Fingerprint::from(&ckey.cert[0]);

        // See if the storage has been published
        if let Some(map) = self.storage.load_full() {
            // Check if we have a certificate with this fingerprint already
            if let Some(v) = map.get(&fp) {
                // Check if its OCSP validity is set
                // Otherwise it hasn't been yet stapled or OCSP response has expired
                if v.ocsp_validity.is_some() {
                    return Some(v.ckey.clone());
                }

                // Return unstapled
                return Some(ckey);
            }
        }

        // In some rare cases of very high load the messages can be lost but since they'll be
        // sent again by subsequent requests - it's not a problem.
        let _ = self.tx.try_send((fp, ckey.clone()));

        // Return the original unstapled cert
        Some(ckey)
    }
}

struct StaplerActor {
    client: Client,
    storage: Storage,
    rx: mpsc::Receiver<(Fingerprint, Arc<CertifiedKey>)>,
    published: Arc<ArcSwapOption<Storage>>,
}

impl StaplerActor {
    async fn refresh(&mut self) {
        if self.storage.is_empty() {
            return;
        }

        let now: DateTime<FixedOffset> = Utc::now().into();

        // Remove all expired certificates from the storage to free up resources
        self.storage.retain(|_, v| v.cert_validity > now);

        let start = Instant::now();
        for v in self.storage.values_mut() {
            if let Some(x) = &v.ocsp_validity {
                // See if this OCSP response is still valid
                if !x.time_to_update(now) {
                    continue;
                }

                // If the validity is about to expire - clear it
                // This makes sure we don't serve expired OCSP responses in Stapler::resolve()
                if x.next_update - now < TimeDelta::hours(1) {
                    v.ocsp_validity = None
                }
            }

            // Stapler::resolve() makes sure that we have at least two certificates in the chain
            let cert = v.ckey.cert[0].as_ref();
            let issuer = v.ckey.cert[1].as_ref();

            // Query the OCSP responder
            let resp = match self.client.query(cert, issuer).await {
                Err(e) => {
                    warn!("OCSP-Stapler: unable to perform OCSP request: {e:#}");
                    continue;
                }

                Ok(v) => v,
            };

            if let CertStatus::Revoked(x) = resp.cert_status {
                warn!("OCSP-Stapler: certificate was revoked: {x:?}");
            }

            // Update the OCSP response on the key
            let mut ckey = v.ckey.as_ref().clone();
            ckey.ocsp = Some(resp.raw);

            // Update values
            v.ckey = Arc::new(ckey);
            v.ocsp_validity = Some(resp.ocsp_validity);
        }

        // Publish the updated storage version
        let new = Arc::new(self.storage.clone());
        self.published.store(Some(new));

        warn!(
            "OCSP-Stapler: certificates refreshed in {}ms",
            start.elapsed().as_millis()
        );
    }

    async fn process_certificate(
        &mut self,
        fp: Fingerprint,
        ckey: Arc<CertifiedKey>,
    ) -> Result<(), Error> {
        #[allow(clippy::map_entry)]
        if self.storage.contains_key(&fp) {
            return Ok(());
        }

        // Parse the DER-encoded cert
        let cert = X509Certificate::from_der(ckey.end_entity_cert().unwrap())
            .context("unable to parse certificate as X.509")?
            .1;

        let cert_validity = DateTime::from_timestamp(cert.validity.not_after.timestamp(), 0)
            .ok_or_else(|| anyhow!("unable to parse NotAfter"))?
            .into();

        let cert = Cert {
            ckey: ckey.clone(),
            cert_validity,
            ocsp_validity: None,
        };

        self.storage.insert(fp, cert);
        self.refresh().await;

        Ok(())
    }

    async fn run(&mut self, token: CancellationToken) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                biased;

                () = token.cancelled() => {
                    warn!("OCSP-Stapler: exiting");
                    return;
                }

                _ = interval.tick() => {
                    self.refresh().await;
                },

                msg = self.rx.recv() => {
                    if let Some((fp, ckey)) = msg {
                        if let Err(e) = self.process_certificate(fp, ckey).await {
                            warn!("OCSP-Stapler: unable to process certificate: {e:#}");
                        }
                    }
                }
            }
        }
    }
}
