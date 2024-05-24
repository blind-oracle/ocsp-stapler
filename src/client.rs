use std::time::Duration;

use anyhow::{anyhow, Context, Error};
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

use super::OcspValidity;

/// OCSP response
pub struct Response {
    pub raw: Vec<u8>,
    pub cert_status: CertStatus,
    pub ocsp_validity: OcspValidity,
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

    /// Fetches the raw OCSP response for the given certificate chain
    pub async fn query_raw(&self, cert: &[u8], issuer: &[u8]) -> Result<OcspResponse, Error> {
        // Prepare OCSP request & URL
        let (ocsp_request, url) =
            prepare_ocsp_request(cert, issuer).context("unable to prepare OCSP request")?;

        // DER-encode it
        let ocsp_request = rasn::der::encode(&ocsp_request)
            .map_err(|e| anyhow!("unable to serialize OCSP request: {e}"))?;

        // Execute HTTP request
        let response = self
            .http_client
            .post(url)
            .header(CONTENT_TYPE, "application/ocsp-request")
            .body(ocsp_request)
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

    /// Fetches the raw OCSP response and returns its validity & status
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
            ocsp_validity: OcspValidity {
                this_update: resp.this_update,
                next_update: resp
                    .next_update
                    .ok_or_else(|| anyhow!("No next-update field in the response"))?,
            },
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use hex_literal::hex;

    const CHAIN: &[u8] = b"-----BEGIN CERTIFICATE-----\n\
    MIIEGzCCAwOgAwIBAgISA6Lvz+ctYY3QxsH2Wtl15VliMA0GCSqGSIb3DQEBCwUA\n\
    MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\n\
    EwJSMzAeFw0yNDA1MjIxODQxNTNaFw0yNDA4MjAxODQxNTJaMBIxEDAOBgNVBAMT\n\
    B2ljcDIuaW8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASQ0Cs7rk/cMH9fVV1w\n\
    RWDruLIRXFunNbBt1DhEneLJyox1gViQ4PUjdclH4SjBtuM4GEYgsqtfjtVmUEZD\n\
    LjDno4ICFDCCAhAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMB\n\
    BggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBT6I71UZqu4cBfDD/pw\n\
    s2RrfxFTIzAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEF\n\
    BQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggr\n\
    BgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzAdBgNVHREEFjAUggkqLmlj\n\
    cDIuaW+CB2ljcDIuaW8wEwYDVR0gBAwwCjAIBgZngQwBAgEwggEEBgorBgEEAdZ5\n\
    AgQCBIH1BIHyAPAAdgA/F0tP1yJHWJQdZRyEvg0S7ZA3fx+FauvBvyiF7PhkbgAA\n\
    AY+h0wjrAAAEAwBHMEUCIEgf/wjunpqoG09SbIyHc4qDdMiOdAlaQkwJtUcGq85h\n\
    AiEA+3Sw0q0bayIl+Ax6+VLFWICCnqXUo6xlUvom1v4RAO8AdgB2/4g/Crb7lVHC\n\
    Ycz1h7o0tKTNuyncaEIKn+ZnTFo6dAAAAY+h0wkvAAAEAwBHMEUCIQCVHm3eG98z\n\
    H3yULVe5dp/+chkCWHP3DW4rV5RQHh2ChAIgKTv4SRNtvZsCA6/urtZeaaXmTe13\n\
    +kQW72HPScbzNSEwDQYJKoZIhvcNAQELBQADggEBAJ5jnRYWQrBz0INPtRxQ5GEJ\n\
    Sfd49/q5ybEnAKFLt1nurOgUBnEa6H3m8J8VGnuRHwHQhEwtNRgMYjkOvdhfU633\n\
    17hfr3ZizpD3S+ZHgcMeI9uzUg58GLxqD8Gj2bS4jRgjWFxVEJ71KPimRgata0iN\n\
    A0SMlr2ZwQWgccxv+jLuVbDOvPMmlhKRr9iBSeMKl7goRPl4uIcWJmhXS/8jOcGY\n\
    KzEI8pX097kn6e2kmHF8KrfH57YrJ2g2/dJ/XZA7SR6UCIFRZL83/J+WjlZKL5hO\n\
    vABp2wcEodYUslfJHEY8u6uYZNXMyUO1j3xYwWE6W7m0IMRR03xCJdeAV+kAPDA=\n\
    -----END CERTIFICATE-----\n\
    -----BEGIN CERTIFICATE-----\n\
    MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\n\
    TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n\
    cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\n\
    WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\n\
    RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
    AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\n\
    R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\n\
    sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\n\
    NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\n\
    Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n\
    /kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\n\
    AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\n\
    Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\n\
    FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\n\
    AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\n\
    Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\n\
    gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\n\
    PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\n\
    ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\n\
    CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\n\
    lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\n\
    avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\n\
    yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\n\
    yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\n\
    hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\n\
    HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\n\
    MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\n\
    nLRbwHOoq7hHwg==\n\
    -----END CERTIFICATE-----\n\
    ";

    #[test]
    fn test_extract_url() {
        let certs = CHAIN.to_vec();
        let certs = rustls_pemfile::certs(&mut certs.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let cert = X509Certificate::from_der(&certs[0]).unwrap().1;

        assert_eq!(
            extract_ocsp_url(&cert),
            Some("http://r3.o.lencr.org".to_string())
        )
    }

    #[test]
    fn test_prepare_request() {
        let certs = CHAIN.to_vec();
        let certs = rustls_pemfile::certs(&mut certs.as_ref())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let (req, url) = prepare_ocsp_request(&certs[0], &certs[1]).unwrap();

        assert_eq!(url.to_string(), "http://r3.o.lencr.org/");

        let expected = OcspRequest {
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
                            &hex!("48DAC9A0FB2BD32D4FF0DE68D2F567B735F9B3C4")[..],
                        ),
                        issuer_key_hash: Bytes::from(
                            &hex!("142EB317B75856CBAE500940E61FAF9D8B14C2C6")[..],
                        ),
                        serial_number: num_bigint::BigInt::from_str(
                            "316781366221747159870971160091460368685410",
                        )
                        .unwrap(),
                    },
                    single_request_extensions: None,
                }],
                request_extensions: None,
            },
            optional_signature: None,
        };

        assert_eq!(req, expected);
    }
}
