use crate::config::RuntimeConfig;
use crate::engine::{Policy, Redactor, sha256_hex};
use crate::formats::validate_structure_preserved;
use crate::input::{InputFile, collect_inputs};
use crate::model::{
    InputFormat, PlaceholderStyle, PrivateRedactionEvent, Profile, RedactedDocument,
    RedactionEvent, RedactionSummary, SkippedFile,
};
use crate::report::{events_jsonl, readme_text, skipped_jsonl, summary_markdown};
use anyhow::{Context, Result, bail};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;

#[derive(Debug)]
pub struct BundleOptions {
    pub profile: Profile,
    pub placeholder_style: PlaceholderStyle,
    pub input_options: crate::input::InputOptions,
    pub runtime_config: RuntimeConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub schema_version: String,
    pub tool_name: String,
    pub tool_version: String,
    pub created_at: String,
    pub profile: String,
    pub policy: String,
    pub input_roots: Vec<String>,
    pub file_count: usize,
    pub redacted_file_count: usize,
    pub skipped_file_count: usize,
    pub redaction_count: usize,
    pub classes: BTreeMap<String, usize>,
    pub redacted_output_hashes: BTreeMap<String, String>,
    pub bundle_hash: String,
}

#[derive(Clone, Debug)]
pub struct BundleResult {
    pub manifest: Manifest,
    pub summary: RedactionSummary,
    pub skipped: Vec<SkippedFile>,
    pub events: Vec<RedactionEvent>,
    pub private_events: Vec<PrivateRedactionEvent>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BundleVerification {
    pub manifest: Manifest,
    pub verified_file_count: usize,
    pub verified_redaction_count: usize,
}

pub fn build_bundle(
    input_roots: &[PathBuf],
    output: &Path,
    options: BundleOptions,
) -> Result<BundleResult> {
    let (inputs, mut skipped) = collect_inputs(input_roots, &options.input_options)?;
    let mut redactor = Redactor::with_detectors(
        Policy::new(options.profile, options.placeholder_style),
        options.runtime_config.detector_set.clone(),
    );
    let mut documents = Vec::new();
    let mut events = Vec::new();
    let mut private_events = Vec::new();
    let mut summary = RedactionSummary::default();

    for input in &inputs {
        let profile = options
            .runtime_config
            .profile_for_path(&input.archive_path, options.profile);
        let document = redactor.redact_text_with_profile(
            &input.content,
            &input.archive_path,
            &input.format,
            profile,
        );
        validate_structure_preserved(&input.format, &input.content, &document.redacted)
            .with_context(|| format!("structured validation failed for {}", input.source_file))?;
        validate_redacted_output(&document, options.profile, options.placeholder_style)
            .with_context(|| {
                format!("post-redaction validation failed for {}", input.source_file)
            })?;
        summary.add_document(&document);
        events.extend(document.events.clone());
        private_events.extend(document.private_events.clone());
        documents.push((input.clone(), document));
    }

    summary.skipped_files = skipped.len();
    sanitize_skipped_metadata(&mut skipped, options.profile, options.placeholder_style);

    let redacted_output_hashes = documents
        .iter()
        .map(|(input, document)| {
            (
                format!("files/{}", input.archive_path),
                sha256_hex(document.redacted.as_bytes()),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let manifest = Manifest {
        schema_version: "1".to_string(),
        tool_name: "safe-bundle".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        profile: options.profile.as_str().to_string(),
        policy: "built-in".to_string(),
        input_roots: input_roots
            .iter()
            .map(|path| {
                sanitize_metadata_value(
                    &path.display().to_string(),
                    options.profile,
                    options.placeholder_style,
                )
            })
            .collect(),
        file_count: summary.scanned_files,
        redacted_file_count: summary.redacted_files,
        skipped_file_count: summary.skipped_files,
        redaction_count: summary.redaction_count,
        classes: summary.by_class.clone(),
        bundle_hash: logical_bundle_hash(&redacted_output_hashes, &events),
        redacted_output_hashes,
    };

    write_zip(
        output,
        &manifest,
        &summary,
        &mut skipped,
        &documents,
        &events,
    )?;

    Ok(BundleResult {
        manifest,
        summary,
        skipped,
        events,
        private_events,
    })
}

pub fn inspect_bundle(path: &Path) -> Result<Manifest> {
    let mut archive = open_bundle(path)?;
    require_bundle_entries(&mut archive)?;
    read_manifest(&mut archive)
}

pub fn verify_bundle(path: &Path) -> Result<BundleVerification> {
    let mut archive = open_bundle(path)?;
    require_bundle_entries(&mut archive)?;
    let manifest = read_manifest(&mut archive)?;
    if manifest.schema_version != "1" {
        bail!(
            "unsupported bundle schema version {}",
            manifest.schema_version
        );
    }

    let checksums = read_string(&mut archive, "checksums.sha256")?;
    let parsed_checksums = parse_checksums(&checksums)?;
    if parsed_checksums != manifest.redacted_output_hashes {
        bail!("checksums.sha256 does not match manifest redacted_output_hashes");
    }

    for (path, expected_hash) in &manifest.redacted_output_hashes {
        let mut file = archive
            .by_name(path)
            .with_context(|| format!("bundle is missing redacted file {path}"))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let actual_hash = sha256_hex(&bytes);
        if &actual_hash != expected_hash {
            bail!("checksum mismatch for {path}");
        }
    }

    let redactions = read_string(&mut archive, "redactions.jsonl")?;
    let events = parse_redactions_jsonl(&redactions)?;
    let logical_hash = logical_bundle_hash(&manifest.redacted_output_hashes, &events);
    if logical_hash != manifest.bundle_hash {
        bail!("bundle_hash does not match manifest files and redactions");
    }
    if events.len() != manifest.redaction_count {
        bail!(
            "manifest redaction_count {} does not match redactions.jsonl count {}",
            manifest.redaction_count,
            events.len()
        );
    }

    Ok(BundleVerification {
        verified_file_count: manifest.redacted_output_hashes.len(),
        verified_redaction_count: events.len(),
        manifest,
    })
}

fn open_bundle(path: &Path) -> Result<zip::ZipArchive<File>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    Ok(zip::ZipArchive::new(file)?)
}

fn require_bundle_entries(archive: &mut zip::ZipArchive<File>) -> Result<()> {
    for required in [
        "manifest.json",
        "summary.md",
        "redactions.jsonl",
        "skipped.jsonl",
        "checksums.sha256",
        "README.txt",
    ] {
        archive
            .by_name(required)
            .with_context(|| format!("bundle is missing {required}"))?;
    }
    Ok(())
}

fn read_manifest(archive: &mut zip::ZipArchive<File>) -> Result<Manifest> {
    let manifest_json = read_string(archive, "manifest.json")?;
    Ok(serde_json::from_str(&manifest_json)?)
}

fn read_string(archive: &mut zip::ZipArchive<File>, name: &str) -> Result<String> {
    let mut file = archive.by_name(name)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

fn parse_checksums(input: &str) -> Result<BTreeMap<String, String>> {
    let mut checksums = BTreeMap::new();
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((hash, path)) = trimmed.split_once("  ") else {
            bail!("invalid checksums.sha256 line {}", index + 1);
        };
        checksums.insert(path.to_string(), hash.to_string());
    }
    Ok(checksums)
}

fn parse_redactions_jsonl(input: &str) -> Result<Vec<RedactionEvent>> {
    let mut events = Vec::new();
    for (index, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        events.push(
            serde_json::from_str(trimmed)
                .with_context(|| format!("invalid redactions.jsonl line {}", index + 1))?,
        );
    }
    Ok(events)
}

fn write_zip(
    output: &Path,
    manifest: &Manifest,
    summary: &RedactionSummary,
    skipped: &mut [SkippedFile],
    documents: &[(InputFile, RedactedDocument)],
    events: &[RedactionEvent],
) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }

    let file =
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    add_file(
        &mut zip,
        options,
        "manifest.json",
        &serde_json::to_string_pretty(manifest)?,
    )?;
    add_file(
        &mut zip,
        options,
        "summary.md",
        &summary_markdown(summary, skipped),
    )?;
    add_file(
        &mut zip,
        options,
        "redactions.jsonl",
        &events_jsonl(events)?,
    )?;
    add_file(&mut zip, options, "skipped.jsonl", &skipped_jsonl(skipped)?)?;
    add_file(&mut zip, options, "checksums.sha256", &checksums(manifest))?;
    add_file(&mut zip, options, "README.txt", readme_text())?;

    for (input, document) in documents {
        let archive_path = format!("files/{}", input.archive_path);
        if archive_path.contains("..")
            || archive_path.starts_with('/')
            || archive_path.starts_with('\\')
        {
            bail!("unsafe archive path {archive_path}");
        }
        add_file(&mut zip, options, &archive_path, &document.redacted)?;
    }

    zip.finish()?;
    Ok(())
}

fn sanitize_skipped_metadata(
    skipped: &mut [SkippedFile],
    profile: Profile,
    placeholder_style: PlaceholderStyle,
) {
    for skipped_file in skipped {
        skipped_file.path = sanitize_metadata_value(&skipped_file.path, profile, placeholder_style);
    }
}

fn sanitize_metadata_value(
    value: &str,
    profile: Profile,
    placeholder_style: PlaceholderStyle,
) -> String {
    let mut redactor = Redactor::new(Policy::new(profile, placeholder_style));
    redactor.redact_text(value, "metadata", "text").redacted
}

fn add_file<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    options: SimpleFileOptions,
    name: &str,
    content: &str,
) -> Result<()> {
    zip.start_file(name, options)?;
    zip.write_all(content.as_bytes())?;
    Ok(())
}

fn checksums(manifest: &Manifest) -> String {
    let mut out = String::new();
    for (path, hash) in &manifest.redacted_output_hashes {
        out.push_str(hash);
        out.push_str("  ");
        out.push_str(path);
        out.push('\n');
    }
    out
}

fn logical_bundle_hash(
    redacted_output_hashes: &BTreeMap<String, String>,
    events: &[RedactionEvent],
) -> String {
    let mut content = String::new();
    for (path, hash) in redacted_output_hashes {
        content.push_str(path);
        content.push('\0');
        content.push_str(hash);
        content.push('\n');
    }
    for event in events {
        content.push_str(&event.redaction_id);
        content.push('\0');
        content.push_str(event.placeholder.as_str());
        content.push('\0');
        content.push_str(event.class.as_str());
        content.push('\n');
    }
    sha256_hex(content.as_bytes())
}

fn validate_redacted_output(
    document: &RedactedDocument,
    profile: Profile,
    placeholder_style: PlaceholderStyle,
) -> Result<()> {
    let mut redactor = Redactor::new(Policy::new(profile, placeholder_style));
    let validation = redactor.redact_text(
        &document.redacted,
        &document.source_file,
        InputFormat::Text.as_str(),
    );
    let leaked = validation
        .events
        .iter()
        .filter(|event| !event.placeholder.starts_with("[REDACTED:"))
        .count();
    if leaked > 0 {
        bail!("final validation found {leaked} residual redaction candidates");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::InputOptions;
    use std::collections::BTreeSet;
    use std::io::Read;

    #[test]
    fn bundle_contains_redacted_files_and_no_public_raw_secret() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("logs");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("app.env"),
            "API_KEY=ghp_abcdefghijklmnopqrstuvwxyz\nUSER=C:\\Users\\Matt\\app\n",
        )
        .unwrap();

        let output = temp.path().join("support.safe-bundle.zip");
        let result = build_bundle(
            &[input],
            &output,
            BundleOptions {
                profile: Profile::Support,
                placeholder_style: PlaceholderStyle::Bracket,
                input_options: InputOptions::default(),
                runtime_config: RuntimeConfig::empty(),
            },
        )
        .unwrap();

        assert_eq!(result.summary.redaction_count, 2);
        let manifest = inspect_bundle(&output).unwrap();
        assert_eq!(manifest.redaction_count, 2);

        let mut archive = zip::ZipArchive::new(File::open(output).unwrap()).unwrap();
        let mut redacted = String::new();
        archive
            .by_name("files/logs/app.env")
            .unwrap()
            .read_to_string(&mut redacted)
            .unwrap();
        assert!(!redacted.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(!redacted.contains("C:\\Users\\Matt"));

        let mut redactions = String::new();
        archive
            .by_name("redactions.jsonl")
            .unwrap()
            .read_to_string(&mut redactions)
            .unwrap();
        assert!(!redactions.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        assert!(redactions.contains(r#""source_file":"logs/app.env""#));
        assert!(!redactions.contains(&temp.path().display().to_string()));
    }

    #[test]
    fn verify_bundle_accepts_valid_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("logs");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("app.env"),
            "API_KEY=ghp_abcdefghijklmnopqrstuvwxyz\n",
        )
        .unwrap();

        let output = temp.path().join("support.safe-bundle.zip");
        build_bundle(
            &[input],
            &output,
            BundleOptions {
                profile: Profile::PublicIssue,
                placeholder_style: PlaceholderStyle::Bracket,
                input_options: InputOptions::default(),
                runtime_config: RuntimeConfig::empty(),
            },
        )
        .unwrap();

        let verification = verify_bundle(&output).unwrap();
        assert_eq!(verification.verified_file_count, 1);
        assert_eq!(verification.verified_redaction_count, 1);
    }

    #[test]
    fn bundle_schema_v1_layout_matches_golden_contract() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("logs");
        fs::create_dir_all(&input).unwrap();
        fs::write(
            input.join("app.env"),
            "API_KEY=ghp_abcdefghijklmnopqrstuvwxyz\n",
        )
        .unwrap();

        let output = temp.path().join("support.safe-bundle.zip");
        build_bundle(
            &[input],
            &output,
            BundleOptions {
                profile: Profile::PublicIssue,
                placeholder_style: PlaceholderStyle::Bracket,
                input_options: InputOptions::default(),
                runtime_config: RuntimeConfig::empty(),
            },
        )
        .unwrap();

        let mut archive = zip::ZipArchive::new(File::open(&output).unwrap()).unwrap();
        let names = archive
            .file_names()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        let expected_names = BTreeSet::from([
            "README.txt".to_string(),
            "checksums.sha256".to_string(),
            "files/logs/app.env".to_string(),
            "manifest.json".to_string(),
            "redactions.jsonl".to_string(),
            "skipped.jsonl".to_string(),
            "summary.md".to_string(),
        ]);
        assert_eq!(names, expected_names);

        let mut manifest_json = String::new();
        archive
            .by_name("manifest.json")
            .unwrap()
            .read_to_string(&mut manifest_json)
            .unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
        let manifest_fields = manifest
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected_manifest_fields = BTreeSet::from([
            "bundle_hash".to_string(),
            "classes".to_string(),
            "created_at".to_string(),
            "file_count".to_string(),
            "input_roots".to_string(),
            "policy".to_string(),
            "profile".to_string(),
            "redacted_file_count".to_string(),
            "redacted_output_hashes".to_string(),
            "redaction_count".to_string(),
            "schema_version".to_string(),
            "skipped_file_count".to_string(),
            "tool_name".to_string(),
            "tool_version".to_string(),
        ]);
        assert_eq!(manifest_fields, expected_manifest_fields);
        assert_eq!(manifest["schema_version"], "1");

        let mut checksums = String::new();
        archive
            .by_name("checksums.sha256")
            .unwrap()
            .read_to_string(&mut checksums)
            .unwrap();
        assert!(checksums.ends_with("  files/logs/app.env\n"));

        let mut redactions = String::new();
        archive
            .by_name("redactions.jsonl")
            .unwrap()
            .read_to_string(&mut redactions)
            .unwrap();
        let redaction_events = parse_redactions_jsonl(&redactions).unwrap();
        assert_eq!(redaction_events.len(), 1);

        verify_bundle(&output).unwrap();
    }

    #[test]
    fn verify_bundle_rejects_checksum_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("broken.safe-bundle.zip");
        let mut hashes = BTreeMap::new();
        hashes.insert("files/example.txt".to_string(), "deadbeef".to_string());
        let manifest = Manifest {
            schema_version: "1".to_string(),
            tool_name: "safe-bundle".to_string(),
            tool_version: "0.0.0-test".to_string(),
            created_at: "2026-05-10T00:00:00Z".to_string(),
            profile: "public-issue".to_string(),
            policy: "built-in".to_string(),
            input_roots: vec!["example".to_string()],
            file_count: 1,
            redacted_file_count: 0,
            skipped_file_count: 0,
            redaction_count: 0,
            classes: BTreeMap::new(),
            redacted_output_hashes: hashes,
            bundle_hash: "not-a-real-logical-hash".to_string(),
        };
        let input = InputFile {
            absolute_path: PathBuf::from("example.txt"),
            source_file: "example.txt".to_string(),
            archive_path: "example.txt".to_string(),
            format: "text".to_string(),
            content: "plain".to_string(),
        };
        let document = RedactedDocument {
            source_file: "example.txt".to_string(),
            source_format: "text".to_string(),
            original_len: 5,
            redacted: "plain".to_string(),
            events: Vec::new(),
            private_events: Vec::new(),
        };
        write_zip(
            &output,
            &manifest,
            &RedactionSummary {
                scanned_files: 1,
                ..RedactionSummary::default()
            },
            &mut [],
            &[(input, document)],
            &[],
        )
        .unwrap();

        let err = verify_bundle(&output).unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"));
    }
}
