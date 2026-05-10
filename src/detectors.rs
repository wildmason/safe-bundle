use crate::model::{Confidence, DetectorInfo, RedactionClass};
use anyhow::{Context, Result};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::LazyLock;

#[derive(Clone, Debug)]
pub struct Candidate {
    pub class: RedactionClass,
    pub confidence: Confidence,
    pub specificity: u8,
    pub detector_id: String,
    pub detector_version: String,
    pub reason: String,
    pub start: usize,
    pub end: usize,
    pub raw: String,
    pub context: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct Detector {
    info: DetectorInfo,
    regex: Regex,
    capture_group: usize,
    context_key_group: Option<usize>,
    specificity: u8,
}

impl Detector {
    fn new(
        id: impl Into<String>,
        class: RedactionClass,
        confidence: Confidence,
        reason: impl Into<String>,
        pattern: &str,
        capture_group: usize,
    ) -> Self {
        Self {
            info: DetectorInfo {
                id: id.into(),
                version: "1".to_string(),
                class,
                confidence,
                reason: reason.into(),
            },
            regex: Regex::new(pattern).expect("detector regex must compile"),
            capture_group,
            context_key_group: None,
            specificity: 0,
        }
    }

    fn with_context_key_group(mut self, group: usize) -> Self {
        self.context_key_group = Some(group);
        self
    }

    fn with_specificity(mut self, specificity: u8) -> Self {
        self.specificity = specificity;
        self
    }
}

#[derive(Clone, Debug)]
pub struct CustomDetectorDefinition {
    pub id: String,
    pub pattern: String,
    pub class: RedactionClass,
    pub confidence: Confidence,
    pub reason: String,
    pub capture_group: usize,
    pub context_key_group: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    literals: Vec<String>,
    regexes: Vec<Regex>,
}

impl Allowlist {
    pub fn new(literals: Vec<String>, regex_patterns: Vec<String>) -> Result<Self> {
        let regexes = regex_patterns
            .into_iter()
            .map(|pattern| {
                Regex::new(&pattern)
                    .with_context(|| format!("invalid allowlist regex pattern {pattern}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { literals, regexes })
    }

    fn is_allowed(&self, raw: &str) -> bool {
        self.literals.iter().any(|literal| literal == raw)
            || self.regexes.iter().any(|regex| regex.is_match(raw))
    }
}

#[derive(Clone, Debug, Default)]
pub struct DetectorSet {
    custom: Vec<Detector>,
    allowlist: Allowlist,
}

impl DetectorSet {
    pub fn new(custom: Vec<CustomDetectorDefinition>, allowlist: Allowlist) -> Result<Self> {
        let custom = custom
            .into_iter()
            .map(Detector::from_custom)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { custom, allowlist })
    }

    pub fn detector_infos(&self) -> Vec<DetectorInfo> {
        DETECTORS
            .iter()
            .chain(self.custom.iter())
            .map(|detector| detector.info.clone())
            .collect()
    }

    pub fn detect(&self, text: &str) -> Vec<Candidate> {
        detect_with(text, self.custom.iter(), &self.allowlist)
    }
}

impl Detector {
    fn from_custom(definition: CustomDetectorDefinition) -> Result<Self> {
        let regex = Regex::new(&definition.pattern)
            .with_context(|| format!("invalid custom detector regex {}", definition.id))?;
        Ok(Self {
            info: DetectorInfo {
                id: definition.id,
                version: "custom".to_string(),
                class: definition.class,
                confidence: definition.confidence,
                reason: definition.reason,
            },
            regex,
            capture_group: definition.capture_group,
            context_key_group: definition.context_key_group,
            specificity: 40,
        })
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
            "escaped-private-key-pem",
            RedactionClass::SecretPrivateKey,
            Confidence::High,
            "escaped PEM private key block",
            r#"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\\n(?:[^"\\]|\\.)*?-----END [A-Z0-9 ]*PRIVATE KEY-----\\n?"#,
            0,
        )
        .with_specificity(20),
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
        .with_context_key_group(1)
        .with_specificity(20),
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
            r#"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|token|api[_-]?key|secret|client_secret|access_token|refresh_token|session|cookie|webhook_secret))\b['"]?\s*[:=]\s*['"]?([^\s'",;{}\[\]]{4,})"#,
            2,
        )
        .with_context_key_group(1),
        Detector::new(
            "secret-header-value",
            RedactionClass::SecretApiKey,
            Confidence::High,
            "secret-like HTTP/HAR header value",
            r#"(?i)"name"\s*:\s*"[^"]*(?:api[-_]?key|token|secret)[^"]*"\s*,\s*"value"\s*:\s*"([^"]{8,})""#,
            1,
        )
        .with_specificity(20),
        Detector::new(
            "aws-access-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "AWS access key id",
            r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b",
            0,
        ),
        Detector::new(
            "aws-secret-access-key-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "AWS secret access key assignment",
            r#"(?i)\b(aws_secret_access_key|aws_secret_key)\b\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
        Detector::new(
            "aws-session-token-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "AWS session token assignment",
            r#"(?i)\b(aws_session_token|aws_security_token)\b\s*[:=]\s*['"]?([A-Za-z0-9/+=]{20,})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
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
            "stripe-webhook-secret",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Stripe webhook signing secret",
            r"\bwhsec_[A-Za-z0-9]{16,}\b",
            0,
        )
        .with_specificity(20),
        Detector::new(
            "npm-token",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "npm token",
            r"\bnpm_[A-Za-z0-9]{20,}\b",
            0,
        ),
        Detector::new(
            "sendgrid-api-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "SendGrid API key",
            r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
            0,
        )
        .with_specificity(20),
        Detector::new(
            "openai-api-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "OpenAI API key",
            r"\bsk-(?:proj-[A-Za-z0-9_-]{20,}|svcacct-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})\b",
            0,
        ),
        Detector::new(
            "datadog-api-key-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Datadog API key assignment",
            r#"(?i)\b(datadog_api_key|dd_api_key)\b\s*[:=]\s*['"]?([a-f0-9]{32})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
        Detector::new(
            "netlify-auth-token-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Netlify auth token assignment",
            r#"(?i)\b(netlify_auth_token|netlify_token)\b\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
        Detector::new(
            "vercel-token-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Vercel token assignment",
            r#"(?i)\b(vercel_token|vercel_auth_token)\b\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
        Detector::new(
            "postmark-token-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Postmark server token assignment",
            r#"(?i)\b(postmark_(?:server_)?token|postmark_api_token)\b\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[A-Za-z0-9]{20,})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
        Detector::new(
            "sentry-auth-token-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Sentry auth token assignment",
            r#"(?i)\b(sentry_auth_token|sentry_token)\b\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
        Detector::new(
            "supabase-service-role-key-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Supabase service role key assignment",
            r#"(?i)\b(supabase_service_role_key|supabase_service_key)\b\s*[:=]\s*['"]?([A-Za-z0-9._-]{20,})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
        Detector::new(
            "twilio-auth-token-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Twilio auth token assignment",
            r#"(?i)\b(twilio_auth_token)\b\s*[:=]\s*['"]?([a-f0-9]{32})"#,
            2,
        )
        .with_context_key_group(1)
        .with_specificity(20),
        Detector::new(
            "anthropic-api-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Anthropic API key",
            r"\bsk-ant-[A-Za-z0-9_-]{10,}\b",
            0,
        ),
        Detector::new(
            "slack-token",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Slack token",
            r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
            0,
        ),
        Detector::new(
            "discord-mfa-token",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Discord MFA token",
            r"\bmfa\.[A-Za-z0-9_-]{20,}\b",
            0,
        ),
        Detector::new(
            "discord-bot-token",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Discord bot token",
            r"\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b",
            0,
        ),
        Detector::new(
            "fly-api-token",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Fly.io API token",
            r"\bFlyV1\s+[A-Za-z0-9._~+/=-]{20,}",
            0,
        ),
        Detector::new(
            "resend-api-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Resend API key",
            r"\bre_[A-Za-z0-9]{20,}\b",
            0,
        ),
        Detector::new(
            "lemon-squeezy-key-value",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Lemon Squeezy key/token assignment",
            r#"(?i)\b(lemon_squeezy|lemonsqueezy|ls)_(?:api_)?(?:key|token|secret)\b\s*[:=]\s*['"]?([^\s'",;{}\[\]]{8,})"#,
            2,
        )
        .with_context_key_group(1),
        Detector::new(
            "gcp-api-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Google API key",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            0,
        ),
        Detector::new(
            "azure-storage-account-key",
            RedactionClass::SecretCloudCredential,
            Confidence::High,
            "Azure storage account key",
            r"(?i)\bAccountKey=([A-Za-z0-9+/=]{20,})",
            1,
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
            "escaped-windows-user-path",
            RedactionClass::IdentityLocalUser,
            Confidence::High,
            "escaped Windows user profile path",
            r"(?i)\b[A-Z]:\\\\Users\\\\([^\\\r\n]+)",
            1,
        )
        .with_specificity(20),
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
    DetectorSet::default().detector_infos()
}

pub fn detect(text: &str) -> Vec<Candidate> {
    DetectorSet::default().detect(text)
}

fn detect_with<'a>(
    text: &str,
    custom: impl Iterator<Item = &'a Detector>,
    allowlist: &Allowlist,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    for detector in DETECTORS.iter().chain(custom) {
        for captures in detector.regex.captures_iter(text) {
            let Some(matched) = captures.get(detector.capture_group) else {
                continue;
            };
            let raw = matched.as_str();
            if raw.is_empty() || raw.starts_with("[REDACTED:") {
                continue;
            }
            if allowlist.is_allowed(raw) {
                continue;
            }

            let mut context = BTreeMap::new();
            if let Some(group) = detector.context_key_group
                && let Some(key) = captures.get(group)
            {
                context.insert("key".to_string(), key.as_str().to_string());
            }

            if detector.info.id == "secret-key-value"
                && !looks_like_generic_secret(raw, context.get("key").map(String::as_str))
            {
                continue;
            }

            candidates.push(Candidate {
                class: detector.info.class,
                confidence: detector.info.confidence,
                specificity: detector.specificity,
                detector_id: detector.info.id.clone(),
                detector_version: detector.info.version.clone(),
                reason: detector.info.reason.clone(),
                start: matched.start(),
                end: matched.end(),
                raw: raw.to_string(),
                context,
            });
        }
    }

    candidates
}

fn looks_like_generic_secret(raw: &str, key: Option<&str>) -> bool {
    let value = raw.trim_matches(|ch| ch == '"' || ch == '\'');
    if value.is_empty() {
        return false;
    }

    let lower_value = value.to_ascii_lowercase();
    if matches!(
        lower_value.as_str(),
        "true"
            | "false"
            | "null"
            | "none"
            | "required"
            | "optional"
            | "enabled"
            | "disabled"
            | "active"
            | "inactive"
            | "default"
            | "example"
            | "changeme"
            | "redacted"
    ) {
        return false;
    }

    let lower_key = key.unwrap_or_default().to_ascii_lowercase();
    if lower_key.contains("policy")
        || lower_key.contains("count")
        || lower_key.contains("enabled")
        || lower_key.contains("disabled")
        || lower_key.contains("required")
    {
        return false;
    }

    let password_like =
        lower_key.contains("password") || lower_key.contains("passwd") || lower_key.contains("pwd");
    let min_len = if password_like { 6 } else { 8 };
    if value.len() < min_len {
        return false;
    }
    if value.len() >= 20 {
        return true;
    }

    let has_lower = value.chars().any(|ch| ch.is_ascii_lowercase());
    let has_upper = value.chars().any(|ch| ch.is_ascii_uppercase());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value
        .chars()
        .any(|ch| !ch.is_ascii_alphanumeric() && !ch.is_whitespace());
    let category_count = [has_lower, has_upper, has_digit, has_symbol]
        .into_iter()
        .filter(|present| *present)
        .count();

    if password_like {
        return category_count >= 2 || value.len() >= 10;
    }

    category_count >= 2 || value.len() >= 16
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
        assert!(infos.iter().any(|info| info.id == "openai-api-key"));
        assert!(infos.iter().any(|info| info.id == "anthropic-api-key"));
        assert!(infos.iter().any(|info| info.id == "resend-api-key"));
    }

    #[test]
    fn finds_provider_specific_tokens() {
        let input = [
            format!("OPENAI_API_KEY={}", ["sk-", "proj-", "abcdefghijklmnopqrstuvwxyz123456"].concat()),
            format!("ANTHROPIC_API_KEY={}", ["sk-", "ant-", "api03-", "abcdefghijklmnopqrstuvwxyz"].concat()),
            format!(
                "SLACK_BOT_TOKEN={}",
                ["xoxb", "-", "123456789012-123456789012-abcdefghijklmnopqrstuvwx"].concat()
            ),
            format!("DISCORD_TOKEN={}", ["mfa", ".", "abcdefghijklmnopqrstuvwxyz123456"].concat()),
            format!(
                "DISCORD_BOT={}",
                [
                    "ABCDEFGHIJKLMNOPQRSTUVWX",
                    ".",
                    "abcdef",
                    ".",
                    "abcdefghijklmnopqrstuvwxyz1234567",
                ]
                .concat()
            ),
            format!("FLY_API_TOKEN={}", ["FlyV1", " ", "abcdefghijklmnopqrstuvwxyz123456"].concat()),
            format!("RESEND_API_KEY={}", ["re", "_", "abcdefghijklmnopqrstuvwxyz123456"].concat()),
            format!(
                "LEMON_SQUEEZY_API_KEY={}",
                ["ls", "_", "live", "_", "abcdefghijklmnopqrstuvwxyz"].concat()
            ),
            format!("GCP_API_KEY={}", ["AI", "za", "abcdefghijklmnopqrstuvwxyz123456789"].concat()),
            "AZURE_STORAGE=DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=abcdefghijklmnopqrstuvwxyz1234567890+/=;EndpointSuffix=core.windows.net".to_string(),
            "AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN".to_string(),
            "AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEGgaCXVzLWVhc3QtMSJGMEQCIDfixture".to_string(),
            "STRIPE_WEBHOOK_SECRET=whsec_abcdefghijklmnopqrstuvwxyz".to_string(),
            "SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz".to_string(),
            "DATADOG_API_KEY=0123456789abcdef0123456789abcdef".to_string(),
            "NETLIFY_AUTH_TOKEN=abcdefghijklmnopqrstuvwxyz123456".to_string(),
            "VERCEL_TOKEN=abcdefghijklmnopqrstuvwxyz123456".to_string(),
            "POSTMARK_SERVER_TOKEN=12345678-1234-1234-1234-123456789abc".to_string(),
            "SENTRY_AUTH_TOKEN=abcdefghijklmnopqrstuvwxyz123456".to_string(),
            "SUPABASE_SERVICE_ROLE_KEY=eyJabcdefghijklmnop.qrstuvwxyz123456.abcdefghijklmnop".to_string(),
            "TWILIO_AUTH_TOKEN=0123456789abcdef0123456789abcdef".to_string(),
            r#"{"private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvFakeFixtureOnly\n-----END PRIVATE KEY-----\n"}"#.to_string(),
        ]
        .join("\n");
        let found = detect(&input);
        let ids = found
            .iter()
            .map(|candidate| candidate.detector_id.as_str())
            .collect::<Vec<_>>();

        for expected in [
            "openai-api-key",
            "anthropic-api-key",
            "slack-token",
            "discord-mfa-token",
            "discord-bot-token",
            "fly-api-token",
            "resend-api-key",
            "lemon-squeezy-key-value",
            "gcp-api-key",
            "azure-storage-account-key",
            "aws-secret-access-key-value",
            "aws-session-token-value",
            "stripe-webhook-secret",
            "sendgrid-api-key",
            "datadog-api-key-value",
            "netlify-auth-token-value",
            "vercel-token-value",
            "postmark-token-value",
            "sentry-auth-token-value",
            "supabase-service-role-key-value",
            "twilio-auth-token-value",
            "escaped-private-key-pem",
        ] {
            assert!(ids.contains(&expected), "missing detector {expected}");
        }
    }

    #[test]
    fn generic_key_value_detector_avoids_common_config_words() {
        let found = detect(
            "password_policy=required\nsecret_enabled=false\ntoken_count=128\nsession=active\n",
        );

        assert!(found.is_empty());
    }
}
