//! The journal: what was done with the CAs — created, imported, certificates issued and revoked,
//! a PKCS#12 or a CA private key handed out, the network key set — and every time the key was
//! handed to the service. Kept encrypted in the data folder ([`super::DataFolder`]), while the
//! service has its key; the log has none of it.
//!
//! A record is flat JSON; only the fields of its event are there:
//!
//! ```json
//! {"at":1763200800,"event":"cert_issued","ca":"xfin-ca","cn":"alice@example.com","serial":7}
//! {"at":1763201000,"event":"cert_revoked","ca":"xfin-ca","cn":"alice@example.com","serial":7}
//! {"at":1763202000,"event":"ca_imported","ca":"xfin-ca","by":"legacy","certificates":12}
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// The most records one read returns.
pub const MAX_LIMIT: usize = 1000;
/// Records one read returns when it names no limit.
pub const DEFAULT_LIMIT: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalEvent {
    /// The data folder was created, with this key.
    Initialized,
    /// The key was handed to the service — after a start — and opened the data folder.
    Unlocked,
    /// `ca` was created.
    CaGenerated,
    /// `ca` was imported, `by` `api` (its certificate and key) or `legacy` (from the plaintext
    /// folder of an earlier version, with its `certificates`).
    CaImported,
    /// `ca` issued `cn` the certificate `serial`.
    CertIssued,
    /// `ca` revoked the certificate `serial` of `cn`.
    CertRevoked,
    /// The certificate `serial` of `cn` was handed out as PKCS#12, with its private key.
    PfxDownloaded,
    /// The private key of `ca` was handed out.
    CaKeyDownloaded,
    /// The network key was set, `by` `new` or `replaced` (a rotation). The key itself is never
    /// journaled.
    NetworkKeySet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    /// When, unix seconds.
    pub at: u64,
    pub event: JournalEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// How many certificate records came with an imported CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificates: Option<usize>,
}

impl JournalRecord {
    /// A record of `event` at `at`, with no other field.
    pub fn new(event: JournalEvent, at: u64) -> Self {
        Self {
            at,
            event,
            ca: None,
            cn: None,
            serial: None,
            by: None,
            certificates: None,
        }
    }

    /// A record of `event` now, about `ca`.
    pub fn of_ca(event: JournalEvent, ca: &str) -> Self {
        let mut record = Self::new(event, unix_now());
        record.ca = Some(ca.to_string());
        record
    }

    /// A record of `event` now, about the certificate `serial` of `cn` issued by `ca`.
    pub fn of_cert(event: JournalEvent, ca: &str, cn: &str, serial: u64) -> Self {
        let mut record = Self::of_ca(event, ca);
        record.cn = Some(cn.to_string());
        record.serial = Some(serial);
        record
    }

    /// Whether the record is one `query` asks for, its limit aside.
    pub fn matches(&self, query: &JournalQuery) -> bool {
        if query.from.is_some_and(|from| self.at < from) {
            return false;
        }
        if query.to.is_some_and(|to| self.at >= to) {
            return false;
        }
        let wanted = |value: &Option<String>| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        if let Some(ca) = wanted(&query.ca) {
            if self.ca.as_deref() != Some(ca.as_str()) {
                return false;
            }
        }
        if let Some(cn) = wanted(&query.cn) {
            if self.cn.as_deref() != Some(cn.as_str()) {
                return false;
            }
        }
        true
    }
}

/// Which records to read — newest first.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct JournalQuery {
    /// From this time on, unix seconds, included.
    pub from: Option<u64>,
    /// Before this time, unix seconds, not included.
    pub to: Option<u64>,
    /// Only the records of this CA.
    pub ca: Option<String>,
    /// Only the records of this CN.
    pub cn: Option<String>,
    /// At most this many: [`DEFAULT_LIMIT`] when not given, never more than [`MAX_LIMIT`].
    pub limit: Option<usize>,
}

impl JournalQuery {
    pub fn limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// What a read found.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct JournalPage {
    /// Newest first.
    pub records: Vec<JournalRecord>,
    /// Lines passed over because they did not open with the key or were not a record.
    pub unreadable: usize,
}

/// Now, unix seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

const DAY_SECS: u64 = 24 * 60 * 60;

/// The UTC month of `unix` (seconds): `yyyy-mm` — what the journal file of the month is named.
pub fn year_month(unix: u64) -> String {
    // Days to the civil date: Howard Hinnant's `civil_from_days`.
    let z = (unix / DAY_SECS) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}")
}

#[cfg(test)]
mod tests {
    use super::{year_month, JournalEvent, JournalQuery, JournalRecord, MAX_LIMIT};

    #[test]
    fn a_record_is_flat_json_with_its_own_fields_only() {
        let mut record = JournalRecord::new(JournalEvent::CertIssued, 1_763_200_800);
        record.ca = Some("xfin-ca".to_string());
        record.cn = Some("alice@example.com".to_string());
        record.serial = Some(7);
        assert_eq!(
            serde_json::to_string(&record).unwrap(),
            r#"{"at":1763200800,"event":"cert_issued","ca":"xfin-ca","cn":"alice@example.com","serial":7}"#
        );
        let back: JournalRecord =
            serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn queries() {
        let mut record = JournalRecord::new(JournalEvent::CertRevoked, 100);
        record.ca = Some("a".to_string());
        record.cn = Some("alice".to_string());
        let all = JournalQuery::default();
        assert!(record.matches(&all));
        assert!(record.matches(&JournalQuery { from: Some(100), to: Some(101), ..all.clone() }));
        assert!(!record.matches(&JournalQuery { from: Some(101), ..all.clone() }));
        assert!(!record.matches(&JournalQuery { to: Some(100), ..all.clone() }));
        assert!(record.matches(&JournalQuery { ca: Some("a".to_string()), ..all.clone() }));
        assert!(!record.matches(&JournalQuery { ca: Some("b".to_string()), ..all.clone() }));
        assert!(record.matches(&JournalQuery { cn: Some(" alice ".to_string()), ..all.clone() }));
        assert!(!record.matches(&JournalQuery { cn: Some("bob".to_string()), ..all.clone() }));
        assert!(record.matches(&JournalQuery { ca: Some(String::new()), ..all.clone() }));
        assert_eq!(all.limit(), 100);
        assert_eq!(JournalQuery { limit: Some(0), ..all.clone() }.limit(), 1);
        assert_eq!(JournalQuery { limit: Some(1_000_000), ..all }.limit(), MAX_LIMIT);
    }

    #[test]
    fn months() {
        assert_eq!(year_month(0), "1970-01");
        assert_eq!(year_month(1_761_951_600), "2025-10"); // 2025-10-31 23:00 UTC
        assert_eq!(year_month(1_764_547_200), "2025-12"); // 2025-12-01 00:00 UTC
        assert_eq!(year_month(1_709_164_800), "2024-02"); // 2024-02-29 00:00 UTC
    }
}
