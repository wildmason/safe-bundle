use crate::detectors::{Allowlist, CustomDetectorDefinition, DetectorSet, detector_infos};
use crate::model::{Confidence, Profile, RedactionClass};
use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const CONFIG_FILE_NAME: &str = ".safe-bundle.toml";

pub fn starter_config_toml() -> &'static str {
    r#"# safe-bundle repository policy.
# Discovery walks from the current directory upward until this file is found.
# Pass --no-config to ignore repository policy for a single command.

version = 1

[allowlist]
literals = []
regexes = []

# Add repository-specific detectors by uncommenting and editing this block.
# [[custom_detectors]]
# id = "ticket-token"
# pattern = "ticket_[A-Za-z0-9_]{12,}"
# class = "secret.api_key"
# confidence = "high"
# reason = "ticket fixture token"
# capture_group = 0

# Use first-match path overrides to preserve more context in selected paths.
# [[path_overrides]]
# pattern = "public/**"
# profile = "internal"
"#
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    version: Option<u32>,
    allowlist: AllowlistConfig,
    custom_detectors: Vec<CustomDetectorConfig>,
    path_overrides: Vec<PathOverrideConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AllowlistConfig {
    literals: Vec<String>,
    regexes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomDetectorConfig {
    id: String,
    pattern: String,
    class: RedactionClass,
    confidence: Confidence,
    reason: String,
    #[serde(default)]
    capture_group: usize,
    #[serde(default)]
    context_key_group: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathOverrideConfig {
    pattern: String,
    profile: Profile,
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub loaded_from: Option<PathBuf>,
    pub detector_set: DetectorSet,
    path_overrides: Vec<PathProfileOverride>,
    stats: RuntimeConfigStats,
}

#[derive(Clone, Debug, Default)]
struct RuntimeConfigStats {
    custom_detector_count: usize,
    allowlist_literal_count: usize,
    allowlist_regex_count: usize,
    path_override_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeConfigSummary {
    pub loaded_from: Option<PathBuf>,
    pub built_in_detector_count: usize,
    pub custom_detector_count: usize,
    pub total_detector_count: usize,
    pub allowlist_literal_count: usize,
    pub allowlist_regex_count: usize,
    pub path_override_count: usize,
}

#[derive(Debug)]
struct PathProfileOverride {
    matcher: GlobSet,
    profile: Profile,
}

impl RuntimeConfig {
    pub fn empty() -> Self {
        Self {
            loaded_from: None,
            detector_set: DetectorSet::default(),
            path_overrides: Vec::new(),
            stats: RuntimeConfigStats::default(),
        }
    }

    pub fn load(explicit_path: Option<&Path>, no_config: bool) -> Result<Self> {
        if no_config {
            return Ok(Self::empty());
        }

        let Some(path) = explicit_path
            .map(|path| Ok(Some(path.to_path_buf())))
            .unwrap_or_else(discover_config)?
        else {
            return Ok(Self::empty());
        };

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        Self::from_toml(&raw, Some(path))
    }

    pub fn from_toml(raw: &str, loaded_from: Option<PathBuf>) -> Result<Self> {
        let config: FileConfig =
            toml::from_str(raw).context("failed to parse safe-bundle config")?;
        if let Some(version) = config.version {
            if version != 1 {
                bail!("unsupported safe-bundle config version {version}");
            }
        }

        let custom_detector_count = config.custom_detectors.len();
        let allowlist_literal_count = config.allowlist.literals.len();
        let allowlist_regex_count = config.allowlist.regexes.len();
        let path_override_count = config.path_overrides.len();

        let custom = validate_custom_detectors(config.custom_detectors)?;
        let allowlist = Allowlist::new(config.allowlist.literals, config.allowlist.regexes)?;
        let detector_set = DetectorSet::new(custom, allowlist)?;
        let path_overrides = config
            .path_overrides
            .into_iter()
            .map(PathProfileOverride::new)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            loaded_from,
            detector_set,
            path_overrides,
            stats: RuntimeConfigStats {
                custom_detector_count,
                allowlist_literal_count,
                allowlist_regex_count,
                path_override_count,
            },
        })
    }

    pub fn profile_for_path(&self, archive_path: &str, default: Profile) -> Profile {
        self.path_overrides
            .iter()
            .find(|override_rule| override_rule.matcher.is_match(archive_path))
            .map(|override_rule| override_rule.profile)
            .unwrap_or(default)
    }

    pub fn summary(&self) -> RuntimeConfigSummary {
        let built_in_detector_count = detector_infos().len();
        RuntimeConfigSummary {
            loaded_from: self.loaded_from.clone(),
            built_in_detector_count,
            custom_detector_count: self.stats.custom_detector_count,
            total_detector_count: self.detector_set.detector_infos().len(),
            allowlist_literal_count: self.stats.allowlist_literal_count,
            allowlist_regex_count: self.stats.allowlist_regex_count,
            path_override_count: self.stats.path_override_count,
        }
    }
}

impl PathProfileOverride {
    fn new(config: PathOverrideConfig) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        builder.add(
            Glob::new(&config.pattern)
                .with_context(|| format!("invalid path override glob {}", config.pattern))?,
        );
        Ok(Self {
            matcher: builder.build()?,
            profile: config.profile,
        })
    }
}

fn discover_config() -> Result<Option<PathBuf>> {
    let mut current = std::env::current_dir().context("failed to resolve current directory")?;
    loop {
        let candidate = current.join(CONFIG_FILE_NAME);
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}

fn validate_custom_detectors(
    configs: Vec<CustomDetectorConfig>,
) -> Result<Vec<CustomDetectorDefinition>> {
    let built_in_ids = detector_infos()
        .into_iter()
        .map(|info| info.id)
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut definitions = Vec::new();

    for config in configs {
        if config.id.trim().is_empty() {
            bail!("custom detector id cannot be empty");
        }
        if built_in_ids.contains(&config.id) {
            bail!(
                "custom detector id {} conflicts with a built-in detector",
                config.id
            );
        }
        if !seen.insert(config.id.clone()) {
            bail!("duplicate custom detector id {}", config.id);
        }
        if config.reason.trim().is_empty() {
            bail!("custom detector {} must include a reason", config.id);
        }

        definitions.push(CustomDetectorDefinition {
            id: config.id,
            pattern: config.pattern,
            class: config.class,
            confidence: config.confidence,
            reason: config.reason,
            capture_group: config.capture_group,
            context_key_group: config.context_key_group,
        });
    }

    Ok(definitions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Policy, Redactor};
    use crate::model::PlaceholderStyle;

    #[test]
    fn loads_custom_detector_and_allowlist() {
        let config = RuntimeConfig::from_toml(
            r#"
version = 1

[allowlist]
literals = ["ticket_keep_this_value"]
regexes = ["SAFE-[0-9]+"]

[[custom_detectors]]
id = "ticket-token"
pattern = "ticket_[A-Za-z0-9_]{12,}"
class = "secret.api_key"
confidence = "high"
reason = "ticket fixture token"
"#,
            None,
        )
        .unwrap();

        let mut redactor = Redactor::with_detectors(
            Policy::new(Profile::PublicIssue, PlaceholderStyle::Bracket),
            config.detector_set,
        );
        let document = redactor.redact_text(
            "token=ticket_redact_this_value token=ticket_keep_this_value SAFE-123",
            "x.env",
            "env",
        );

        assert!(!document.redacted.contains("ticket_redact_this_value"));
        assert!(document.redacted.contains("ticket_keep_this_value"));
        assert!(document.redacted.contains("SAFE-123"));
        assert!(
            document
                .events
                .iter()
                .any(|event| event.detector_id == "ticket-token")
        );
    }

    #[test]
    fn applies_first_matching_path_override() {
        let config = RuntimeConfig::from_toml(
            r#"
[[path_overrides]]
pattern = "public/**"
profile = "internal"

[[path_overrides]]
pattern = "**"
profile = "strict"
"#,
            None,
        )
        .unwrap();

        assert_eq!(
            config.profile_for_path("public/example.log", Profile::PublicIssue),
            Profile::Internal
        );
        assert_eq!(
            config.profile_for_path("private/example.log", Profile::PublicIssue),
            Profile::Strict
        );
    }

    #[test]
    fn rejects_unknown_fields_and_unsupported_versions() {
        let unknown = RuntimeConfig::from_toml(
            r#"
version = 1
mystery = true
"#,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(unknown.contains("failed to parse safe-bundle config"));

        let unsupported = RuntimeConfig::from_toml("version = 2\n", None)
            .unwrap_err()
            .to_string();
        assert!(unsupported.contains("unsupported safe-bundle config version 2"));
    }

    #[test]
    fn starter_config_is_valid_version_one_toml() {
        let config = RuntimeConfig::from_toml(starter_config_toml(), None).unwrap();

        assert!(config.loaded_from.is_none());
        assert_eq!(
            config.profile_for_path("anything.env", Profile::PublicIssue),
            Profile::PublicIssue
        );
    }

    #[test]
    fn reports_config_summary_counts() {
        let config = RuntimeConfig::from_toml(
            r#"
version = 1

[allowlist]
literals = ["ticket_keep_this_value"]
regexes = ["SAFE-[0-9]+"]

[[custom_detectors]]
id = "ticket-token"
pattern = "ticket_[A-Za-z0-9_]{12,}"
class = "secret.api_key"
confidence = "high"
reason = "ticket fixture token"

[[path_overrides]]
pattern = "public/**"
profile = "internal"
"#,
            Some(PathBuf::from(".safe-bundle.toml")),
        )
        .unwrap();

        let summary = config.summary();

        assert_eq!(
            summary.loaded_from,
            Some(PathBuf::from(".safe-bundle.toml"))
        );
        assert_eq!(summary.custom_detector_count, 1);
        assert_eq!(
            summary.total_detector_count,
            summary.built_in_detector_count + 1
        );
        assert_eq!(summary.allowlist_literal_count, 1);
        assert_eq!(summary.allowlist_regex_count, 1);
        assert_eq!(summary.path_override_count, 1);
    }
}
