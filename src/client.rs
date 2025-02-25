use std::time::Duration;

use anyhow::{anyhow, Context, Error};
use base64::prelude::*;
use bytes::Bytes;
use http::{header::CONTENT_TYPE, StatusCode};
use rasn::types::Oid;
use rasn_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request,
    TbsRequest, Version,
};
use rasn_pkix::AlgorithmIdentifier;
use sha1::{Digest, Sha1};
use url::Url;
use x509_parser::{oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP, prelude::*};

use super::Validity;

/// OCSP response
pub struct Response {
    /// Raw OCSP response body.
    /// Useful e.g. for stapling
    pub raw: Vec<u8>,
    /// OCSP response validity interval
    pub ocsp_validity: Validity,
    /// Certificate revocation status
    pub cert_status: CertStatus,
}

/// Extracts OCSP responder URL from the given certificate
fn extract_ocsp_url(cert: &X509Certificate) -> Option<String> {
    cert.extensions()
        .iter()
        .find_map(|x| {
            if let ParsedExtension::AuthorityInfoAccess(v) = x.parsed_extension() {
                Some(v)
            } else {
                None
            }
        })?
        .accessdescs
        .iter()
        .filter(|x| x.access_method == OID_PKIX_ACCESS_DESCRIPTOR_OCSP)
        .find_map(|x| {
            if let GeneralName::URI(v) = x.access_location {
                Some(v.to_string())
            } else {
                None
            }
        })
}

/// Prepares the OCSP request for given cert/issuer pair
fn prepare_ocsp_request(cert: &[u8], issuer: &[u8]) -> Result<(OcspRequest, Url), Error> {
    // Parse the DER-encoded cert & issuer
    let cert = X509Certificate::from_der(cert)
        .context("unable to parse cert")?
        .1;
    let issuer = X509Certificate::from_der(issuer)
        .context("unable to parse issuer")?
        .1;

    // Extract OCSP responder URL
    let url =
        Url::parse(&extract_ocsp_url(&cert).ok_or_else(|| anyhow!("unable to extract OCSP URL"))?)
            .context("unable to parse OCSP URL")?;

    // LetsEncrypt supports only lightweight OCSP profile with SHA1 exclusively.
    // Since its purpose here is non-cryptographic - it's not a security issue.
    //
    // See:
    // - https://github.com/letsencrypt/boulder/issues/5523#issuecomment-877301162
    // - https://datatracker.ietf.org/doc/html/rfc5019
    let hash_algorithm = AlgorithmIdentifier {
        algorithm: Oid::ISO_IDENTIFIED_ORGANISATION_OIW_SECSIG_ALGORITHM_SHA1.to_owned(),
        parameters: None,
    };

    // Calculate the hashes required for OCSP request
    let issuer_name_hash = Bytes::copy_from_slice(Sha1::digest(cert.issuer.as_raw()).as_slice());
    let issuer_key_hash =
        Bytes::copy_from_slice(Sha1::digest(&issuer.public_key().subject_public_key).as_slice());

    // Prepare the request
    let req_cert = CertId {
        hash_algorithm,
        serial_number: cert.serial.clone().into(),
        issuer_name_hash,
        issuer_key_hash,
    };

    let request = Request {
        req_cert,
        single_request_extensions: None,
    };

    let tbs_request = TbsRequest {
        version: Version::ZERO,
        requestor_name: None,
        request_list: vec![request],
        request_extensions: None,
    };

    Ok((
        OcspRequest {
            tbs_request,
            optional_signature: None,
        },
        url,
    ))
}

/// OCSP client
pub struct Client {
    http_client: reqwest::Client,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Creates a new OCSP client with a default Reqwest client
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .connect_timeout(Duration::from_millis(3000))
                .timeout(Duration::from_millis(6000))
                .build()
                .unwrap(),
        }
    }

    /// Creates a new OCSP client using provided Reqwest client
    pub const fn new_with_client(http_client: reqwest::Client) -> Self {
        Self { http_client }
    }

    async fn execute(&self, url: Url, ocsp_request: OcspRequest) -> Result<OcspResponse, Error> {
        // DER-encode it
        let ocsp_request = rasn::der::encode(&ocsp_request)
            .map_err(|e| anyhow!("unable to serialize OCSP request: {e}"))?;

        // Execute HTTP request
        // Send using GET if it's <= 255 bytes as required by
        // https://datatracker.ietf.org/doc/html/rfc5019
        let request = if ocsp_request.len() <= 255 {
            // Encode the request as Base64 and append it to the URL
            let ocsp_request = BASE64_STANDARD.encode(ocsp_request);
            let url = url
                .join(&ocsp_request)
                .context("unable to append base64 request")?;

            self.http_client.get(url)
        } else {
            self.http_client.post(url).body(ocsp_request)
        };

        let response = request
            .header(CONTENT_TYPE, "application/ocsp-request")
            .send()
            .await
            .context("HTTP request failed")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow!("Incorrect HTTP code: {}", response.status()));
        }

        let body = response
            .bytes()
            .await
            .context("unable to read OCSP response body")?;

        // Parse the response
        let ocsp_response: OcspResponse = rasn::der::decode(&body)
            .map_err(|e| anyhow!("unable to decode OcspResponse: {e:#}"))?;

        Ok(ocsp_response)
    }

    /// Fetches the raw OCSP response for the given certificate chain.
    /// Certificates must be DER-encoded.
    pub async fn query_raw(&self, cert: &[u8], issuer: &[u8]) -> Result<OcspResponse, Error> {
        // Prepare OCSP request & URL
        let (ocsp_request, url) =
            prepare_ocsp_request(cert, issuer).context("unable to prepare OCSP request")?;

        self.execute(url, ocsp_request).await
    }

    /// Fetches the raw OCSP response and returns its validity & status.
    /// Certificates must be DER-encoded.
    pub async fn query(&self, cert: &[u8], issuer: &[u8]) -> Result<Response, Error> {
        let ocsp_response = self
            .query_raw(cert, issuer)
            .await
            .context("Unable to perform OCSP query")?;

        if ocsp_response.status != OcspResponseStatus::Successful {
            return Err(anyhow!(
                "Incorrect OCSP response status: {:?}",
                ocsp_response.status
            ));
        }

        // DER-encode it
        let raw = rasn::der::encode(&ocsp_response)
            .map_err(|e| anyhow!("unable to serialize OCSP response: {e}"))?;

        let ocsp_basic: BasicOcspResponse = rasn::der::decode(
            &ocsp_response
                .bytes
                .ok_or_else(|| anyhow!("empty OCSP response"))?
                .response,
        )
        .map_err(|e| anyhow!("unable to decode BasicOcspResponse: {e}"))?;

        if ocsp_basic.tbs_response_data.responses.len() != 1 {
            return Err(anyhow!(
                "OCSP response should contain exactly one certificate"
            ));
        }

        let resp = ocsp_basic.tbs_response_data.responses[0].clone();

        Ok(Response {
            raw,
            cert_status: resp.cert_status,
            ocsp_validity: Validity {
                not_before: resp.this_update,
                not_after: resp
                    .next_update
                    .ok_or_else(|| anyhow!("No next-update field in the response"))?,
            },
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::str::FromStr;

    use super::*;

    use hex_literal::hex;
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use rustls::{crypto::ring, sign::CertifiedKey};

    const OCSP_REQUEST: &[u8] = include_bytes!("../test/ocsp_request.bin");
    const OCSP_RESPONSE: &[u8] = include_bytes!("../test/ocsp_response.bin");
    const CHAIN: &[u8] = include_bytes!("../test/chain.pem");
    const KEY: &[u8] = include_bytes!("../test/key.pem");

    fn test_request() -> OcspRequest {
        OcspRequest {
            tbs_request: TbsRequest {
                version: Version::ZERO,
                requestor_name: None,
                request_list: vec![Request {
                    req_cert: CertId {
                        hash_algorithm: AlgorithmIdentifier {
                            algorithm: Oid::ISO_IDENTIFIED_ORGANISATION_OIW_SECSIG_ALGORITHM_SHA1
                                .to_owned(),
                            parameters: None,
                        },
                        issuer_name_hash: Bytes::from(
                            &hex!("36175FAA02C887BDD95CA13549512D1E97FADFA9")[..],
                        ),
                        issuer_key_hash: Bytes::from(
                            &hex!("6691287B8D8654BAF6203197AEC491E9AFB70BCB")[..],
                        ),
                        serial_number: num_bigint::BigInt::from_str(
                            "3819096869935823013274658159093914787918510",
                        )
                        .unwrap(),
                    },
                    single_request_extensions: None,
                }],
                request_extensions: None,
            },
            optional_signature: None,
        }
    }

    pub(crate) fn test_ckey() -> CertifiedKey {
        let certs = CHAIN.to_vec();
        let certs = rustls_pemfile::certs(&mut certs.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let key = KEY.to_vec();
        let key = rustls_pemfile::private_key(&mut key.as_ref())
            .unwrap()
            .unwrap();

        let key = ring::sign::any_supported_type(&key).unwrap();
        CertifiedKey::new(certs, key)
    }

    #[test]
    fn test_extract_url() {
        let certs = CHAIN.to_vec();
        let certs = rustls_pemfile::certs(&mut certs.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let cert = X509Certificate::from_der(&certs[0]).unwrap().1;

        assert_eq!(
            extract_ocsp_url(&cert),
            Some("http://stg-e5.o.lencr.org".to_string())
        )
    }

    #[test]
    fn test_prepare_request() {
        let certs = CHAIN.to_vec();
        let certs = rustls_pemfile::certs(&mut certs.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let (ocsp_request, url) = prepare_ocsp_request(&certs[0], &certs[1]).unwrap();

        assert_eq!(url.to_string(), "http://stg-e5.o.lencr.org/");
        assert_eq!(ocsp_request, test_request());
        assert_eq!(rasn::der::encode(&ocsp_request).unwrap(), OCSP_REQUEST);
    }

    #[tokio::test]
    async fn test_execute() {
        let server = Server::run();

        server.expect(
            Expectation::matching(request::method("GET"))
                .respond_with(status_code(200).body(OCSP_RESPONSE)),
        );

        let client = Client::new();
        let ocsp_response = client
            .execute(Url::parse(&server.url_str("/")).unwrap(), test_request())
            .await
            .unwrap();

        assert_eq!(OCSP_RESPONSE, rasn::der::encode(&ocsp_response).unwrap());
    }
}
