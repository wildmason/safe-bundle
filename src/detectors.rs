use crate::model::{Confidence, DetectorInfo, RedactionClass};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Clone, Debug)]
pub struct Candidate {
    pub class: RedactionClass,
    pub confidence: Confidence,
    pub detector_id: &'static str,
    pub detector_version: &'static str,
    pub reason: &'static str,
    pub start: usize,
    pub end: usize,
    pub raw: String,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug)]
struct Detector {
    info: DetectorInfo,
    regex: Regex,
    capture_group: usize,
    context_key_group: Option<usize>,
}

impl Detector {
    fn new(
        id: &'static str,
        class: RedactionClass,
        confidence: Confidence,
        reason: &'static str,
        pattern: &str,
        capture_group: usize,
    ) -> Self {
        Self {
            info: DetectorInfo {
                id,
                version: "1",
                class,
                confidence,
                reason,
            },
            regex: Regex::new(pattern).expect("detector regex must compile"),
            capture_group,
            context_key_group: None,
        }
    }

    fn with_context_key_group(mut self, group: usize) -> Self {
        self.context_key_group = Some(group);
        self
    }
}

static DETECTORS: LazyLock<Vec<Detector>> = LazyLock::new(|| {
    vec![
        Detector::new(
            "private-key-pem",
            RedactionClass::SecretPrivateKey,
            Confidence::High,
            "PEM private key block",
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            0,
        ),
        Detector::new(
            "authorization-bearer",
            RedactionClass::SecretAuthToken,
            Confidence::High,
            "Authorization bearer token",
            r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{10,})",
            1,
        ),
        Detector::new(
            "jwt-token",
            RedactionClass::SecretAuthToken,
            Confidence::High,
            "JWT-like token",
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            0,
        ),
        Detector::new(
            "database-url-kv",
            RedactionClass::SecretConnectionString,
            Confidence::High,
            "connection string in key/value pair",
            r#"(?i)\b(database_url|postgres_url|postgresql_url|mysql_url|mongodb_url|redis_url|amqp_url|smtp_url)\b\s*[:=]\s*['"]?([^\s'",;]+)"#,
            2,
        )
        .with_context_key_group(1),
        Detector::new(
            "connection-string",
            RedactionClass::SecretConnectionString,
            Confidence::High,
            "connection string URI",
            r#"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|smtp)://[^\s'"<>]+"#,
            0,
        ),
        Detector::new(
            "url-password",
            RedactionClass::SecretPassword,
            Confidence::High,
            "password segment in authority URL",
            r"://[^:\s/@]+:([^@\s/]+)@",
            1,
        ),
        Detector::new(
            "secret-key-value",
            RedactionClass::SecretPassword,
            Confidence::High,
            "secret-like key/value assignment",
            r#"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|client_secret|access_token|refresh_token|session|cookie|webhook_secret)\b\s*[:=]\s*['"]?([^\s'",;{}\[\]]{4,})"#,
            2,
        )
        .with_context_key_group(1),
        Detector::new(
            "aws-access-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "AWS access key id",
            r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b",
            0,
        ),
        Detector::new(
            "github-token",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "GitHub token",
            r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
            0,
        ),
        Detector::new(
            "stripe-secret-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Stripe secret or restricted key",
            r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
            0,
        ),
        Detector::new(
            "npm-token",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "npm token",
            r"\bnpm_[A-Za-z0-9]{20,}\b",
            0,
        ),
        Detector::new(
            "windows-user-path",
            RedactionClass::IdentityLocalUser,
            Confidence::High,
            "Windows user profile path",
            r"(?i)\b[A-Z]:\\Users\\([^\\\r\n]+)",
            1,
        ),
        Detector::new(
            "unix-home-path",
            RedactionClass::IdentityLocalUser,
            Confidence::High,
            "Unix home directory path",
            r"/home/([A-Za-z0-9._-]+)",
            1,
        ),
        Detector::new(
            "private-ipv4",
            RedactionClass::IdentityHost,
            Confidence::High,
            "private IPv4 address",
            r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b",
            0,
        ),
        Detector::new(
            "contact-email",
            RedactionClass::IdentityContact,
            Confidence::Medium,
            "email address",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            0,
        ),
        Detector::new(
            "internal-url",
            RedactionClass::NetworkEndpoint,
            Confidence::Medium,
            "internal or local URL",
            r#"(?i)\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[A-Za-z0-9.-]+\.(?:local|internal|corp))(?:/[^\s'"<>]*)?"#,
            0,
        ),
    ]
});

pub fn detector_infos() -> Vec<DetectorInfo> {
    DETECTORS
        .iter()
        .map(|detector| detector.info.clone())
        .collect()
}

pub fn detect(text: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    for detector in DETECTORS.iter() {
        for captures in detector.regex.captures_iter(text) {
            let Some(matched) = captures.get(detector.capture_group) else {
                continue;
            };
            let raw = matched.as_str();
            if raw.is_empty() || raw.starts_with("[REDACTED:") {
                continue;
            }

            let mut context = BTreeMap::new();
            if let Some(group) = detector.context_key_group
                && let Some(key) = captures.get(group)
            {
                context.insert("key".to_string(), key.as_str().to_string());
            }

            candidates.push(Candidate {
                class: detector.info.class,
                confidence: detector.info.confidence,
                detector_id: detector.info.id,
                detector_version: detector.info.version,
                reason: detector.info.reason,
                start: matched.start(),
                end: matched.end(),
                raw: raw.to_string(),
                context,
            });
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_common_secret_shapes() {
        let found = detect(
            "Authorization: Bearer abcdefghij12345\nDATABASE_URL=postgres://u:p@example/db\n",
        );
        assert!(
            found
                .iter()
                .any(|c| c.class == RedactionClass::SecretAuthToken)
        );
        assert!(
            found
                .iter()
                .any(|c| c.class == RedactionClass::SecretConnectionString)
        );
    }

    #[test]
    fn exposes_rule_catalog() {
        let infos = detector_infos();
        assert!(infos.iter().any(|info| info.id == "private-key-pem"));
        assert!(infos.iter().any(|info| info.id == "windows-user-path"));
    }
}
