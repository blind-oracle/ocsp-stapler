use std::{
    collections::BTreeMap,
    fmt::{self, Display},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use chrono::{DateTime, FixedOffset, Utc};
use rasn_ocsp::CertStatus;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha1::{Digest, Sha1};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, warn};
use x509_parser::prelude::*;

#[cfg(feature = "prometheus")]
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_vec_with_registry, HistogramVec, IntCounterVec, IntGaugeVec, Registry,
};

#[cfg(feature = "prometheus")]
use itertools::Itertools;

use super::{client::Client, Validity, LEEWAY};

type Storage = BTreeMap<Fingerprint, Cert>;

// Uniquely identifies the certificate, contains SHA-1 of the whole certificate body
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Fingerprint([u8; 20]);

impl From<&CertifiedKey> for Fingerprint {
    fn from(v: &CertifiedKey) -> Self {
        let digest = Sha1::digest(v.cert[0].as_ref());
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

#[cfg(feature = "prometheus")]
#[derive(Clone)]
struct Metrics {
    resolves: IntCounterVec,
    ocsp_requests: IntCounterVec,
    ocsp_requests_duration: HistogramVec,
    certificate_count: IntGaugeVec,
}

#[cfg(feature = "prometheus")]
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

            ocsp_requests_duration: register_histogram_vec_with_registry!(
                format!("ocsp_requests_duration"),
                format!("Observes OCSP requests duration"),
                &["status"],
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
    #[cfg(feature = "prometheus")]
    metrics: Option<Metrics>,
}

impl Stapler {
    /// Creates a Stapler with a default OCSP Client and no metrics
    #[cfg(feature = "prometheus")]
    pub fn new(inner: Arc<dyn ResolvesServerCert>) -> Self {
        Self::new_with_client_and_registry(inner, Client::new(), None)
    }

    /// Creates a Stapler with a default OCSP Client and Registry
    #[cfg(feature = "prometheus")]
    pub fn new_with_registry(inner: Arc<dyn ResolvesServerCert>, registry: &Registry) -> Self {
        Self::new_with_client_and_registry(inner, Client::new(), Some(registry))
    }

    /// Creates a Stapler with a provided OCSP Client and no metrics
    #[cfg(feature = "prometheus")]
    pub fn new_with_client(inner: Arc<dyn ResolvesServerCert>, client: Client) -> Self {
        Self::new_with_client_and_registry(inner, client, None)
    }

    /// Creates a Stapler with a provided OCSP Client and Registry
    #[cfg(feature = "prometheus")]
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

    /// Creates a Stapler with a default OCSP Client and no metrics
    #[cfg(not(feature = "prometheus"))]
    pub fn new(inner: Arc<dyn ResolvesServerCert>) -> Self {
        Self::new_with_client(inner, Client::new())
    }

    /// Creates a Stapler with a default OCSP Client and no metrics (without Prometheus support)
    #[cfg(not(feature = "prometheus"))]
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

    /// Preloads the certificate into the Stapler before the request to resolve() comes.
    /// This allows e.g. to load certificates with `Must-Staple` extension in a way that
    /// when the first request comes they're already stapled.
    /// Has no effect if the same certificate was already preloaded. Silently discards the certificate
    /// if it's not correct (doens't have the issuer, out of validity window etc)
    pub fn preload(&self, ckey: Arc<CertifiedKey>) {
        if ckey.cert.len() < 2 {
            return;
        }

        let fp = Fingerprint::from(ckey.as_ref());
        let _ = self.tx.try_send((fp, ckey));
    }

    /// Returns the certificate revocation status of the provided CertifiedKey.
    /// It will be None if no successful OCSP request was made.
    pub fn status(&self, ckey: Arc<CertifiedKey>) -> Option<CertStatus> {
        if ckey.cert.len() < 2 {
            return None;
        }

        let fp = Fingerprint::from(ckey.as_ref());
        Some(self.storage.load_full()?.get(&fp)?.status.clone())
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
        let fp = Fingerprint::from(ckey.as_ref());

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
        #[cfg(feature = "prometheus")]
        let (ckey, stapled) = self.staple(ckey);

        #[cfg(not(feature = "prometheus"))]
        let (ckey, _stapled) = self.staple(ckey);

        // Record metrics
        #[cfg(feature = "prometheus")]
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
        if !x.past_half_validity(now) {
            return Ok(RefreshResult::StillValid);
        }
    }

    // Stapler makes sure that we have at least two certificates in the chain
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
    cert.ocsp_validity = Some(resp.ocsp_validity);

    Ok(RefreshResult::Refreshed)
}

struct StaplerActor {
    client: Client,
    storage: Storage,
    rx: mpsc::Receiver<(Fingerprint, Arc<CertifiedKey>)>,
    published: Arc<ArcSwapOption<Storage>>,
    #[cfg(feature = "prometheus")]
    metrics: Option<Metrics>,
}

impl StaplerActor {
    async fn refresh(&mut self, now: DateTime<FixedOffset>) {
        if self.storage.is_empty() {
            return;
        }

        // Remove all expired certificates from the storage to free up resources
        self.storage.retain(|_, v| v.cert_validity.valid(now));

        for cert in self.storage.values_mut() {
            let start = Instant::now();
            let res = refresh_certificate(&self.client, now, cert).await;

            // Record metrics
            #[cfg(feature = "prometheus")]
            if let Some(v) = &self.metrics {
                let lbl = &[if res.is_err() { "error" } else { "ok" }];

                v.ocsp_requests_duration
                    .with_label_values(lbl)
                    .observe(start.elapsed().as_secs_f64());

                v.ocsp_requests.with_label_values(lbl).inc()
            };

            match res {
                Ok(v) => {
                    if v == RefreshResult::Refreshed {
                        info!(
                            "OCSP-Stapler: certificate [{cert}] was refreshed ({}) in {}ms",
                            cert.ocsp_validity.as_ref().unwrap(),
                            start.elapsed().as_millis()
                        );
                    }
                }
                Err(e) => warn!("OCSP-Stapler: unable to refresh certificate [{cert}]: {e:#}"),
            }

            // If the validity is about to expire for whatever reason - clear it.
            // This makes sure we don't serve expired OCSP responses in Stapler::resolve()
            if let Some(v) = &cert.ocsp_validity {
                if v.not_after - now < LEEWAY {
                    info!("OCSP-Stapler: certificate [{cert}] OCSP response has expired");
                    cert.ocsp_validity = None;
                }
            }
        }

        // Publish the updated storage version
        let new = Arc::new(self.storage.clone());
        self.published.store(Some(new));

        // Record some metrics
        #[cfg(feature = "prometheus")]
        if let Some(m) = &self.metrics {
            let status = self.storage.values().map(|x| x.status.clone()).counts();

            for (k, v) in status {
                m.certificate_count
                    .with_label_values(&[&format!("{k:?}")])
                    .set(v as i64);
            }
        }
    }

    fn add_certificate(
        &mut self,
        fp: Fingerprint,
        ckey: Arc<CertifiedKey>,
        now: DateTime<FixedOffset>,
    ) -> Result<bool, Error> {
        if self.storage.contains_key(&fp) {
            return Ok(false);
        }

        // Parse the DER-encoded certificate
        let cert = X509Certificate::from_der(ckey.end_entity_cert().unwrap())
            .context("unable to parse certificate as X.509")?
            .1;

        let cert_validity = Validity::try_from(&cert.validity).context(format!(
            "unable to parse certificate [{}] validity",
            cert.subject
        ))?;

        if !cert_validity.valid(now) {
            return Err(anyhow!(
                "the certificate [{}] is not valid at current time",
                cert.subject
            ));
        }

        let cert = Cert {
            ckey: ckey.clone(),
            subject: cert.subject.to_string(),
            status: CertStatus::Unknown(()),
            cert_validity,
            ocsp_validity: None,
        };

        self.storage.insert(fp, cert);
        Ok(true)
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
                        let now = Utc::now().into();
                        if let Err(e) = self.add_certificate(fp, ckey, now) {
                            warn!("OCSP-Stapler: unable to process certificate: {e:#}");
                        } else {
                            self.refresh(now).await;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rustls::crypto::ring;

    #[tokio::test]
    async fn test_add_certificate() {
        // Install a cryptography provider, otherwise the OCSP stapler would panic
        ring::default_provider()
            .install_default()
            .unwrap_or_default();

        let ckey = crate::client::test::test_ckey();
        let storage = Arc::new(ArcSwapOption::empty());
        let (_, rx) = mpsc::channel(1024);

        let mut actor = StaplerActor {
            client: Client::new(),
            storage: BTreeMap::new(),
            rx,
            published: storage.clone(),
            metrics: None,
        };

        let fp = Fingerprint::from(&ckey);
        let ckey = Arc::new(ckey);

        // Check that invalid certificate date fails
        let now = DateTime::parse_from_rfc3339("2024-05-25T00:00:00-00:00").unwrap();
        assert!(actor
            .add_certificate(fp.clone(), ckey.clone(), now)
            .is_err());

        // Make sure that both additions succeed and second returns false
        let now = DateTime::parse_from_rfc3339("2024-05-28T00:00:00-00:00").unwrap();
        assert!(actor
            .add_certificate(fp.clone(), ckey.clone(), now)
            .unwrap());
        assert!(!actor
            .add_certificate(fp.clone(), ckey.clone(), now)
            .unwrap());
    }
}
