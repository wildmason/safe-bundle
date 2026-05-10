use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum Profile {
    #[default]
    Support,
    PublicIssue,
    LlmPrompt,
    Internal,
    Strict,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Support => "support",
            Self::PublicIssue => "public-issue",
            Self::LlmPrompt => "llm-prompt",
            Self::Internal => "internal",
            Self::Strict => "strict",
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum InputFormat {
    #[default]
    Auto,
    Text,
    Env,
    Json,
    Jsonl,
    Yaml,
    Toml,
    Ini,
    Diff,
    Curl,
    Http,
    Har,
}

impl InputFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Text => "text",
            Self::Env => "env",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Yaml => "yaml",
            Self::Toml => "toml",
            Self::Ini => "ini",
            Self::Diff => "diff",
            Self::Curl => "curl",
            Self::Http => "http",
            Self::Har => "har",
        }
    }
}

impl fmt::Display for InputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum SummaryFormat {
    #[default]
    Text,
    Json,
    Markdown,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum PlaceholderStyle {
    #[default]
    Bracket,
    Compact,
    JsonSafe,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum FailOn {
    Findings,
    LowConfidence,
    ValidationError,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum RedactionClass {
    #[serde(rename = "secret.api_key")]
    SecretApiKey,
    #[serde(rename = "secret.auth_token")]
    SecretAuthToken,
    #[serde(rename = "secret.private_key")]
    SecretPrivateKey,
    #[serde(rename = "secret.password")]
    SecretPassword,
    #[serde(rename = "secret.cloud_credential")]
    SecretCloudCredential,
    #[serde(rename = "secret.connection_string")]
    SecretConnectionString,
    #[serde(rename = "identity.local_user")]
    IdentityLocalUser,
    #[serde(rename = "identity.host")]
    IdentityHost,
    #[serde(rename = "identity.contact")]
    IdentityContact,
    #[serde(rename = "business.customer_data")]
    BusinessCustomerData,
    #[serde(rename = "network.endpoint")]
    NetworkEndpoint,
    #[serde(rename = "payload.body")]
    PayloadBody,
}

impl RedactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretApiKey => "secret.api_key",
            Self::SecretAuthToken => "secret.auth_token",
            Self::SecretPrivateKey => "secret.private_key",
            Self::SecretPassword => "secret.password",
            Self::SecretCloudCredential => "secret.cloud_credential",
            Self::SecretConnectionString => "secret.connection_string",
            Self::IdentityLocalUser => "identity.local_user",
            Self::IdentityHost => "identity.host",
            Self::IdentityContact => "identity.contact",
            Self::BusinessCustomerData => "business.customer_data",
            Self::NetworkEndpoint => "network.endpoint",
            Self::PayloadBody => "payload.body",
        }
    }

    pub fn placeholder_label(self) -> String {
        self.as_str().to_ascii_uppercase()
    }

    pub fn is_secret(self) -> bool {
        matches!(
            self,
            Self::SecretApiKey
                | Self::SecretAuthToken
                | Self::SecretPrivateKey
                | Self::SecretPassword
                | Self::SecretCloudCredential
                | Self::SecretConnectionString
        )
    }

    pub fn sensitivity(self) -> u8 {
        match self {
            Self::SecretPrivateKey => 100,
            Self::SecretCloudCredential => 95,
            Self::SecretAuthToken | Self::SecretApiKey | Self::SecretPassword => 90,
            Self::SecretConnectionString => 85,
            Self::BusinessCustomerData | Self::PayloadBody => 70,
            Self::IdentityContact | Self::IdentityLocalUser => 60,
            Self::NetworkEndpoint | Self::IdentityHost => 50,
        }
    }
}

impl fmt::Display for RedactionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceRegion {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl Default for SourceRegion {
    fn default() -> Self {
        Self {
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionEvent {
    pub redaction_id: String,
    pub placeholder: String,
    pub class: RedactionClass,
    pub confidence: Confidence,
    pub detector_id: String,
    pub detector_version: String,
    pub reason: String,
    pub source_file: String,
    pub source_format: String,
    pub original_span: SourceSpan,
    #[serde(default)]
    pub source_region: SourceRegion,
    pub redacted_span: SourceSpan,
    pub original_length: usize,
    pub length_bucket: String,
    pub context: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateRedactionEvent {
    pub redaction_id: String,
    pub placeholder: String,
    pub class: RedactionClass,
    pub detector_id: String,
    pub source_file: String,
    pub original_span: SourceSpan,
    pub raw_sha256: String,
    pub original_length: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactedDocument {
    pub source_file: String,
    pub source_format: String,
    pub original_len: usize,
    pub redacted: String,
    pub events: Vec<RedactionEvent>,
    pub private_events: Vec<PrivateRedactionEvent>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RedactionSummary {
    pub scanned_files: usize,
    pub redacted_files: usize,
    pub skipped_files: usize,
    pub redaction_count: usize,
    pub validation_errors: usize,
    pub by_class: BTreeMap<String, usize>,
    pub by_confidence: BTreeMap<String, usize>,
}

impl RedactionSummary {
    pub fn add_document(&mut self, document: &RedactedDocument) {
        self.scanned_files += 1;
        if !document.events.is_empty() {
            self.redacted_files += 1;
        }
        self.redaction_count += document.events.len();
        for event in &document.events {
            *self
                .by_class
                .entry(event.class.as_str().to_string())
                .or_default() += 1;
            *self
                .by_confidence
                .entry(event.confidence.as_str().to_string())
                .or_default() += 1;
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SkippedFile {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DetectorInfo {
    pub id: String,
    pub version: String,
    pub class: RedactionClass,
    pub confidence: Confidence,
    pub reason: String,
}
