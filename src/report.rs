use crate::engine::sha256_hex;
use crate::model::{
    Confidence, PrivateRedactionEvent, RedactionEvent, RedactionSummary, SkippedFile,
};
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn summary_text(summary: &RedactionSummary) -> String {
    let mut lines = vec![
        format!("Files scanned: {}", summary.scanned_files),
        format!("Files redacted: {}", summary.redacted_files),
        format!("Files skipped: {}", summary.skipped_files),
        format!("Redactions: {}", summary.redaction_count),
    ];
    if summary.validation_errors > 0 {
        lines.push(format!("Validation errors: {}", summary.validation_errors));
    }

    if !summary.by_class.is_empty() {
        lines.push("Redactions by class:".to_string());
        for (class, count) in &summary.by_class {
            lines.push(format!("  {class}: {count}"));
        }
    }

    lines.join("\n")
}

pub fn summary_markdown(summary: &RedactionSummary, skipped: &[SkippedFile]) -> String {
    let mut out = String::new();
    out.push_str("# Safe Bundle Summary\n\n");
    out.push_str("| Metric | Count |\n");
    out.push_str("|---|---:|\n");
    out.push_str(&format!("| Files scanned | {} |\n", summary.scanned_files));
    out.push_str(&format!(
        "| Files redacted | {} |\n",
        summary.redacted_files
    ));
    out.push_str(&format!("| Files skipped | {} |\n", summary.skipped_files));
    out.push_str(&format!("| Redactions | {} |\n", summary.redaction_count));
    if summary.validation_errors > 0 {
        out.push_str(&format!(
            "| Validation errors | {} |\n",
            summary.validation_errors
        ));
    }

    if !summary.by_class.is_empty() {
        out.push_str("\n## Redactions by Class\n\n");
        out.push_str("| Class | Count |\n");
        out.push_str("|---|---:|\n");
        for (class, count) in &summary.by_class {
            out.push_str(&format!("| `{class}` | {count} |\n"));
        }
    }

    if !skipped.is_empty() {
        out.push_str("\n## Skipped Files\n\n");
        out.push_str("| Path | Reason |\n");
        out.push_str("|---|---|\n");
        for skipped_file in skipped {
            out.push_str(&format!(
                "| `{}` | {} |\n",
                escape_markdown_table(&skipped_file.path),
                escape_markdown_table(&skipped_file.reason)
            ));
        }
    }

    out.push_str("\n## Limits\n\n");
    out.push_str("This bundle is a developer safety artifact, not a legal de-identification guarantee. It redacts supported high-confidence classes and preserves diagnostic structure where possible.\n");
    out
}

pub fn events_jsonl(events: &[RedactionEvent]) -> Result<String> {
    let mut out = String::new();
    for event in events {
        out.push_str(&serde_json::to_string(event)?);
        out.push('\n');
    }
    Ok(out)
}

pub fn sarif_json(events: &[RedactionEvent]) -> Result<String> {
    let mut rules = BTreeMap::new();
    for event in events {
        rules.entry(event.detector_id.clone()).or_insert_with(|| {
            json!({
                "id": event.detector_id,
                "name": event.detector_id,
                "shortDescription": {
                    "text": event.reason,
                },
                "properties": {
                    "precision": sarif_precision(event.confidence),
                    "tags": [
                        "safe-bundle",
                        event.class.as_str(),
                    ],
                },
            })
        });
    }

    let results = events
        .iter()
        .map(|event| {
            json!({
                "ruleId": event.detector_id,
                "level": sarif_level(event.confidence),
                "message": {
                    "text": format!(
                        "{} redacted {} as {}.",
                        event.detector_id,
                        event.class.as_str(),
                        event.placeholder
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": sarif_uri(&event.source_file),
                            },
                            "region": {
                                "startLine": event.source_region.start_line,
                                "startColumn": event.source_region.start_column,
                                "endLine": event.source_region.end_line,
                                "endColumn": event.source_region.end_column,
                            },
                        },
                    },
                ],
                "partialFingerprints": {
                    "safeBundleFinding": sarif_fingerprint(event),
                },
                "properties": {
                    "class": event.class.as_str(),
                    "confidence": event.confidence.as_str(),
                    "redactionId": event.redaction_id,
                    "sourceFormat": event.source_format,
                },
            })
        })
        .collect::<Vec<_>>();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "safe-bundle",
                        "informationUri": "https://github.com/wildmason/safe-bundle",
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "rules": rules.into_values().collect::<Vec<Value>>(),
                    },
                },
                "results": results,
            },
        ],
    });
    Ok(serde_json::to_string_pretty(&sarif)?)
}

pub fn private_events_json(events: &[PrivateRedactionEvent]) -> Result<String> {
    Ok(serde_json::to_string_pretty(events)?)
}

pub fn skipped_jsonl(skipped: &[SkippedFile]) -> Result<String> {
    let mut out = String::new();
    for file in skipped {
        out.push_str(&serde_json::to_string(file)?);
        out.push('\n');
    }
    Ok(out)
}

pub fn readme_text() -> &'static str {
    "Safe support bundle generated by safe-bundle.\n\nThis archive contains redacted files only. It does not contain original files or raw secret values. Review summary.md and redactions.jsonl before sharing publicly.\n"
}

fn escape_markdown_table(input: &str) -> String {
    input.replace('|', "\\|").replace('\n', " ")
}

fn sarif_level(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "error",
        Confidence::Medium => "warning",
        Confidence::Low => "note",
    }
}

fn sarif_precision(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "very-high",
        Confidence::Medium => "high",
        Confidence::Low => "medium",
    }
}

fn sarif_uri(path: &str) -> String {
    path.trim_start_matches("./").replace('\\', "/")
}

fn sarif_fingerprint(event: &RedactionEvent) -> String {
    sha256_hex(
        format!(
            "{}\0{}\0{}\0{}\0{}",
            event.source_file,
            event.detector_id,
            event.class.as_str(),
            event.original_span.start,
            event.original_span.end
        )
        .as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Policy, Redactor};
    use crate::model::{PlaceholderStyle, Profile};

    #[test]
    fn sarif_uses_public_metadata_and_source_regions() {
        let mut redactor =
            Redactor::new(Policy::new(Profile::PublicIssue, PlaceholderStyle::Bracket));
        let document = redactor.redact_text(
            "before\nAPI_KEY=ghp_abcdefghijklmnopqrstuvwxyz\n",
            "src/app.env",
            "env",
        );

        let sarif = sarif_json(&document.events).unwrap();
        assert!(!sarif.contains("ghp_abcdefghijklmnopqrstuvwxyz"));
        let value: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            2
        );
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/app.env"
        );
    }
}
