#![warn(clippy::all)]
#![warn(clippy::nursery)]

pub mod client;
pub mod stapler;

use std::fmt::Display;

pub use client::Client;
pub use stapler::Stapler;

use anyhow::{anyhow, Error};
use chrono::{DateTime, FixedOffset, TimeDelta};
use x509_parser::certificate;

/// Allow some time inconsistencies
pub(crate) const LEEWAY: TimeDelta = TimeDelta::minutes(5);

/// OCSP response validity interval
#[derive(Clone, Debug)]
pub struct Validity {
    pub not_before: DateTime<FixedOffset>,
    pub not_after: DateTime<FixedOffset>,
}

impl Display for Validity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.not_before, self.not_after)
    }
}

impl TryFrom<&certificate::Validity> for Validity {
    type Error = Error;
    fn try_from(v: &certificate::Validity) -> Result<Self, Self::Error> {
        let not_before = DateTime::from_timestamp(v.not_before.timestamp(), 0)
            .ok_or_else(|| anyhow!("unable to parse not_before"))?
            .into();

        let not_after = DateTime::from_timestamp(v.not_after.timestamp(), 0)
            .ok_or_else(|| anyhow!("unable to parse not_after"))?
            .into();

        Ok(Self {
            not_before,
            not_after,
        })
    }
}

impl Validity {
    /// Check if we're already past the half of this validity duration
    pub fn time_to_update(&self, now: DateTime<FixedOffset>) -> bool {
        now >= self.not_before + ((self.not_after - self.not_before) / 2)
    }

    /// Check if it's valid
    pub fn valid(&self, now: DateTime<FixedOffset>) -> bool {
        now >= (self.not_before - LEEWAY) && now <= (self.not_after + LEEWAY)
    }
}
