use crate::detectors::{Candidate, DetectorSet};
use crate::model::{
    Confidence, PlaceholderStyle, PrivateRedactionEvent, Profile, RedactedDocument, RedactionClass,
    RedactionEvent, SourceSpan,
};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug)]
pub struct Policy {
    pub profile: Profile,
    pub placeholder_style: PlaceholderStyle,
}

impl Policy {
    pub fn new(profile: Profile, placeholder_style: PlaceholderStyle) -> Self {
        Self {
            profile,
            placeholder_style,
        }
    }

    pub fn should_redact(&self, candidate: &Candidate) -> bool {
        if candidate.confidence == Confidence::High && candidate.class.is_secret() {
            return true;
        }

        match self.profile {
            Profile::Internal => {
                candidate.confidence == Confidence::High && candidate.class.is_secret()
            }
            Profile::Support => {
                matches!(
                    candidate.class,
                    RedactionClass::IdentityLocalUser | RedactionClass::IdentityHost
                ) && candidate.confidence == Confidence::High
            }
            Profile::PublicIssue | Profile::LlmPrompt => {
                candidate.confidence.rank() >= Confidence::Medium.rank()
            }
            Profile::Strict => true,
        }
    }
}

#[derive(Debug)]
pub struct Redactor {
    policy: Policy,
    detectors: DetectorSet,
    placeholders: PlaceholderAllocator,
    next_event_id: usize,
}

impl Redactor {
    pub fn new(policy: Policy) -> Self {
        Self::with_detectors(policy, DetectorSet::default())
    }

    pub fn with_detectors(policy: Policy, detectors: DetectorSet) -> Self {
        Self {
            policy: policy.clone(),
            detectors,
            placeholders: PlaceholderAllocator::new(policy.placeholder_style),
            next_event_id: 1,
        }
    }

    pub fn redact_text(
        &mut self,
        text: &str,
        source_file: impl Into<String>,
        source_format: impl Into<String>,
    ) -> RedactedDocument {
        self.redact_text_with_profile(text, source_file, source_format, self.policy.profile)
    }

    pub fn redact_text_with_profile(
        &mut self,
        text: &str,
        source_file: impl Into<String>,
        source_format: impl Into<String>,
        profile: Profile,
    ) -> RedactedDocument {
        let source_file = source_file.into();
        let source_format = source_format.into();
        let policy = Policy {
            profile,
            placeholder_style: self.policy.placeholder_style,
        };
        let candidates = resolve_overlaps(
            self.detectors
                .detect(text)
                .into_iter()
                .filter(|candidate| policy.should_redact(candidate))
                .collect(),
        );

        let mut redacted = String::with_capacity(text.len());
        let mut events = Vec::new();
        let mut private_events = Vec::new();
        let mut cursor = 0;

        for candidate in candidates {
            if candidate.start < cursor {
                continue;
            }

            redacted.push_str(&text[cursor..candidate.start]);
            let redacted_start = redacted.len();
            let placeholder = self
                .placeholders
                .placeholder_for(candidate.class, candidate.raw.as_str());
            redacted.push_str(&placeholder);
            let redacted_end = redacted.len();

            let redaction_id = format!("redaction:{}", self.next_event_id);
            self.next_event_id += 1;

            events.push(RedactionEvent {
                redaction_id: redaction_id.clone(),
                placeholder: placeholder.clone(),
                class: candidate.class,
                confidence: candidate.confidence,
                detector_id: candidate.detector_id.clone(),
                detector_version: candidate.detector_version.clone(),
                reason: candidate.reason.clone(),
                source_file: source_file.clone(),
                source_format: source_format.clone(),
                original_span: SourceSpan {
                    start: candidate.start,
                    end: candidate.end,
                },
                redacted_span: SourceSpan {
                    start: redacted_start,
                    end: redacted_end,
                },
                original_length: candidate.raw.len(),
                length_bucket: length_bucket(candidate.raw.len()).to_string(),
                context: candidate.context.clone(),
            });

            private_events.push(PrivateRedactionEvent {
                redaction_id,
                placeholder,
                class: candidate.class,
                detector_id: candidate.detector_id,
                source_file: source_file.clone(),
                original_span: SourceSpan {
                    start: candidate.start,
                    end: candidate.end,
                },
                raw_sha256: sha256_hex(candidate.raw.as_bytes()),
                original_length: candidate.raw.len(),
            });

            cursor = candidate.end;
        }

        redacted.push_str(&text[cursor..]);

        RedactedDocument {
            source_file,
            source_format,
            original_len: text.len(),
            redacted,
            events,
            private_events,
        }
    }
}

#[derive(Debug)]
struct PlaceholderAllocator {
    style: PlaceholderStyle,
    by_raw: HashMap<(RedactionClass, String), String>,
    class_counts: BTreeMap<RedactionClass, usize>,
}

impl PlaceholderAllocator {
    fn new(style: PlaceholderStyle) -> Self {
        Self {
            style,
            by_raw: HashMap::new(),
            class_counts: BTreeMap::new(),
        }
    }

    fn placeholder_for(&mut self, class: RedactionClass, raw: &str) -> String {
        let key = (class, raw.to_string());
        if let Some(existing) = self.by_raw.get(&key) {
            return existing.clone();
        }

        let count = self.class_counts.entry(class).or_default();
        *count += 1;
        let placeholder = match self.style {
            PlaceholderStyle::Bracket => {
                format!("[REDACTED:{}:{}]", class.placeholder_label(), count)
            }
            PlaceholderStyle::Compact => format!("<{}:{}>", class.as_str(), count),
            PlaceholderStyle::JsonSafe => {
                format!(
                    "__REDACTED_{}_{}__",
                    class.placeholder_label().replace('.', "_"),
                    count
                )
            }
        };
        self.by_raw.insert(key, placeholder.clone());
        placeholder
    }
}

fn resolve_overlaps(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by_key(|candidate| {
        (
            candidate.start,
            Reverse(candidate.class.sensitivity()),
            Reverse(candidate.confidence.rank()),
            Reverse(candidate.specificity),
            Reverse(candidate.end.saturating_sub(candidate.start)),
            candidate.detector_id.clone(),
        )
    });

    let mut selected: Vec<Candidate> = Vec::new();
    for candidate in candidates {
        if selected.iter().any(|existing| {
            ranges_overlap(candidate.start, candidate.end, existing.start, existing.end)
        }) {
            continue;
        }
        selected.push(candidate);
    }

    selected.sort_by_key(|candidate| candidate.start);
    selected
}

fn ranges_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

fn length_bucket(len: usize) -> &'static str {
    match len {
        0..=8 => "0-8",
        9..=16 => "9-16",
        17..=32 => "17-32",
        33..=64 => "33-64",
        65..=128 => "65-128",
        _ => "129+",
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_without_public_raw_value() {
        let mut redactor = Redactor::new(Policy::new(Profile::Support, PlaceholderStyle::Bracket));
        let document =
            redactor.redact_text("API_KEY=ghp_abcdefghijklmnopqrstuvwxyz", "x.env", "env");

        assert!(!document.redacted.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(document.redacted.contains("[REDACTED:SECRET."));
        assert_eq!(document.events.len(), 1);
        let public_json = serde_json::to_string(&document.events).unwrap();
        assert!(!public_json.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert_eq!(document.private_events.len(), 1);
    }

    #[test]
    fn placeholders_are_stable_within_run() {
        let mut redactor = Redactor::new(Policy::new(Profile::Support, PlaceholderStyle::Bracket));
        let document = redactor.redact_text(
            "token=abcdefghij12345 token=abcdefghij12345",
            "x.env",
            "env",
        );

        assert_eq!(document.events.len(), 2);
        assert_eq!(
            document.events[0].placeholder,
            document.events[1].placeholder
        );
    }

    #[test]
    fn support_profile_redacts_local_identity_but_not_email() {
        let mut redactor = Redactor::new(Policy::new(Profile::Support, PlaceholderStyle::Bracket));
        let document =
            redactor.redact_text(r"C:\Users\Matt\app.log matt@example.com", "log.txt", "text");

        assert!(!document.redacted.contains(r"C:\Users\Matt"));
        assert!(document.redacted.contains("matt@example.com"));
    }

    #[test]
    fn public_issue_profile_redacts_email() {
        let mut redactor =
            Redactor::new(Policy::new(Profile::PublicIssue, PlaceholderStyle::Bracket));
        let document = redactor.redact_text("contact matt@example.com", "log.txt", "text");

        assert!(!document.redacted.contains("matt@example.com"));
        assert!(
            document
                .events
                .iter()
                .any(|event| event.class == RedactionClass::IdentityContact)
        );
    }
}
