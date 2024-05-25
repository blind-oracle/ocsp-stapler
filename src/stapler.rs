use std::{
    collections::BTreeMap,
    fmt::{self, Display},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use chrono::{DateTime, FixedOffset, Utc};
use itertools::Itertools;
use prometheus::{
    register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_vec_with_registry, Histogram, IntCounterVec, IntGaugeVec, Registry,
};
use rasn_ocsp::CertStatus;
use rustls::{
    pki_types::CertificateDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha1::{Digest, Sha1};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, warn};
use x509_parser::prelude::*;

use super::{client::Client, Validity, LEEWAY};

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

#[derive(PartialEq, Eq)]
enum RefreshResult {
    StillValid,
    Refreshed,
}

#[derive(Clone)]
struct Cert {
    ckey: Arc<CertifiedKey>,
    subject: String,
    status: CertStatus,
    cert_validity: Validity,
    ocsp_validity: Option<Validity>,
}

impl Display for Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.subject)
    }
}

#[derive(Clone)]
struct Metrics {
    resolves: IntCounterVec,
    ocsp_requests: IntCounterVec,
    refresh_duration: Histogram,
    certificate_count: IntGaugeVec,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        Self {
            resolves: register_int_counter_vec_with_registry!(
                format!("ocsp_resolves_total"),
                format!("Counts the number of certificate resolve requests"),
                &["stapled"],
                registry
            )
            .unwrap(),

            ocsp_requests: register_int_counter_vec_with_registry!(
                format!("ocsp_requests_total"),
                format!("Counts the number of OCSP requests"),
                &["status"],
                registry
            )
            .unwrap(),

            refresh_duration: register_histogram_with_registry!(
                format!("ocsp_refresh_duration"),
                format!("Observes OCSP refresh duration"),
                registry
            )
            .unwrap(),

            certificate_count: register_int_gauge_vec_with_registry!(
                format!("ocsp_certificate_count"),
                format!("Current number of certificates in storage"),
                &["status"],
                registry
            )
            .unwrap(),
        }
    }
}

/// Implements OCSP certificate stapling
pub struct Stapler {
    tx: mpsc::Sender<(Fingerprint, Arc<CertifiedKey>)>,
    storage: Arc<ArcSwapOption<Storage>>,
    inner: Arc<dyn ResolvesServerCert>,
    tracker: TaskTracker,
    token: CancellationToken,
    metrics: Option<Metrics>,
}

impl Stapler {
    /// Creates a Stapler with a default OCSP Client and no metrics
    pub fn new(inner: Arc<dyn ResolvesServerCert>) -> Self {
        Self::new_with_client_and_registry(inner, Client::new(), None)
    }

    /// Creates a Stapler with a default OCSP Client and Registry
    pub fn new_with_registry(inner: Arc<dyn ResolvesServerCert>, registry: &Registry) -> Self {
        Self::new_with_client_and_registry(inner, Client::new(), Some(registry))
    }

    /// Creates a Stapler with a provided OCSP Client and Registry
    pub fn new_with_client_and_registry(
        inner: Arc<dyn ResolvesServerCert>,
        client: Client,
        registry: Option<&Registry>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        let storage = Arc::new(ArcSwapOption::empty());
        let tracker = TaskTracker::new();
        let token = CancellationToken::new();
        let metrics = registry.map(Metrics::new);

        let mut actor = StaplerActor {
            client,
            storage: BTreeMap::new(),
            rx,
            published: storage.clone(),
            metrics: metrics.clone(),
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
            metrics,
        }
    }

    /// Tells the background worker to stop and waits until it does
    pub async fn stop(&self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }

    fn staple(&self, ckey: Arc<CertifiedKey>) -> (Arc<CertifiedKey>, bool) {
        // Check that we have at least two certificates in the chain.
        // Otherwise we can't staple it since we need an issuer certificate too.
        // In this case just return it back unstapled.
        if ckey.cert.len() < 2 {
            return (ckey, false);
        }

        // Compute the fingerprint
        let fp = Fingerprint::from(&ckey.cert[0]);

        // See if the storage is already published
        if let Some(map) = self.storage.load_full() {
            // Check if we have a certificate with this fingerprint
            if let Some(v) = map.get(&fp) {
                // Check if its OCSP validity is set
                // Otherwise it hasn't been yet stapled or OCSP response has expired
                if v.ocsp_validity.is_some() {
                    return (v.ckey.clone(), true);
                }

                // Return unstapled
                return (ckey, false);
            }
        }

        // In some rare cases of very high load the messages can be lost but since they'll be
        // sent again by subsequent requests - it's not a problem.
        let _ = self.tx.try_send((fp, ckey.clone()));

        // Return the original unstapled cert
        (ckey, false)
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
        // Try to get the cert from the wrapped resolver
        let ckey = self.inner.resolve(client_hello)?;

        // Process it through stapler
        let (ckey, stapled) = self.staple(ckey);

        // Record metrics
        if let Some(v) = &self.metrics {
            v.resolves
                .with_label_values(&[if stapled { "yes" } else { "no" }])
                .inc();
        }

        Some(ckey)
    }
}

async fn refresh_certificate(
    client: &Client,
    now: DateTime<FixedOffset>,
    cert: &mut Cert,
) -> Result<RefreshResult, Error> {
    // Check if this OCSP response is still valid
    if let Some(x) = &cert.ocsp_validity {
        if !x.time_to_update(now) {
            return Ok(RefreshResult::StillValid);
        }
    }

    // Stapler::resolve() makes sure that we have at least two certificates in the chain
    let end_entity = cert.ckey.cert[0].as_ref();
    let issuer = cert.ckey.cert[1].as_ref();

    // Query the OCSP responder
    let resp = client
        .query(end_entity, issuer)
        .await
        .context("unable to perform OCSP request")?;

    if !resp.ocsp_validity.valid(now) {
        return Err(anyhow!("the OCSP response is not valid at current time"));
    }

    // Update the OCSP response on the key
    let mut ckey = cert.ckey.as_ref().clone();
    ckey.ocsp = Some(resp.raw);

    // Update values
    cert.ckey = Arc::new(ckey);
    cert.status = resp.cert_status;

    Ok(RefreshResult::Refreshed)
}

struct StaplerActor {
    client: Client,
    storage: Storage,
    rx: mpsc::Receiver<(Fingerprint, Arc<CertifiedKey>)>,
    published: Arc<ArcSwapOption<Storage>>,
    metrics: Option<Metrics>,
}

impl StaplerActor {
    async fn refresh(&mut self, now: DateTime<FixedOffset>) {
        if self.storage.is_empty() {
            return;
        }

        let start = Instant::now();

        // Remove all expired certificates from the storage to free up resources
        self.storage.retain(|_, v| v.cert_validity.valid(now));

        for cert in self.storage.values_mut() {
            let r = refresh_certificate(&self.client, now, cert).await;

            // Record the result
            if let Some(v) = &self.metrics {
                v.ocsp_requests
                    .with_label_values(&[if r.is_err() { "error" } else { "ok" }])
                    .inc()
            };

            match r {
                Ok(v) => {
                    if v == RefreshResult::Refreshed {
                        info!("OCSP-Stapler: certificate [{cert}] was refreshed");
                    }
                }
                Err(e) => warn!("OCSP-Stapler: unable to refresh certificate [{cert}]: {e:#}"),
            }

            // If the validity is about to expire for whatever reason - clear it.
            // This makes sure we don't serve expired OCSP responses in Stapler::resolve()
            if let Some(v) = &cert.ocsp_validity {
                if v.not_after - now < LEEWAY {
                    cert.ocsp_validity = None;
                }
            }
        }

        // Publish the updated storage version
        let new = Arc::new(self.storage.clone());
        self.published.store(Some(new));

        // Record some metrics
        if let Some(m) = &self.metrics {
            let status = self.storage.values().map(|x| x.status.clone()).counts();

            for (k, v) in status {
                m.certificate_count
                    .with_label_values(&[&format!("{k:?}")])
                    .set(v as i64);
            }

            m.refresh_duration.observe(start.elapsed().as_secs_f64());
        }

        warn!(
            "OCSP-Stapler: certificates refreshed in {}ms",
            start.elapsed().as_millis()
        );
    }

    async fn add_certificate(
        &mut self,
        fp: Fingerprint,
        ckey: Arc<CertifiedKey>,
    ) -> Result<(), Error> {
        if self.storage.contains_key(&fp) {
            return Ok(());
        }

        // Parse the DER-encoded certificate
        let cert = X509Certificate::from_der(ckey.end_entity_cert().unwrap())
            .context("unable to parse certificate as X.509")?
            .1;

        let cert_validity =
            Validity::try_from(&cert.validity).context("unable to parse certificate validity")?;

        if !cert_validity.valid(Utc::now().into()) {
            return Err(anyhow!("The certificate is not valid at current time"));
        }

        let cert = Cert {
            ckey: ckey.clone(),
            subject: cert.subject.to_string(),
            status: CertStatus::Unknown(()),
            cert_validity,
            ocsp_validity: None,
        };

        self.storage.insert(fp, cert);
        self.refresh(Utc::now().into()).await;

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
                    self.refresh(Utc::now().into()).await;
                },

                msg = self.rx.recv() => {
                    if let Some((fp, ckey)) = msg {
                        if let Err(e) = self.add_certificate(fp, ckey).await {
                            warn!("OCSP-Stapler: unable to process certificate: {e:#}");
                        }
                    }
                }
            }
        }
    }
}
